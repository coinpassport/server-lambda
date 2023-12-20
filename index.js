const { randomBytes } = require('crypto');
const https = require('https');
const AWS = require('aws-sdk');
const Web3 = require('web3');
const Stripe = require('stripe');


const abi = require('./VerificationV2.json');
const chains = require('./chains.json');

const Bucket = 'coinpassportv2.test';
const return_url = 'http://localhost:3000/app';

const s3 = new AWS.S3({apiVersion: '2006-03-01'});
const stripeTest = Stripe(process.env.STRIPE_SECRET);
const stripeRestrictedTest = Stripe(process.env.STRIPE_RESTRICTED);

exports.handler = async (event) => {
    console.log(event);
    const request = JSON.parse(event.body);
    if(!(request.chainId in chains)) return {
        statusCode: 404,
        body: JSON.stringify({ error: 'Invalid chain' }),
    };
    const stripe = stripeTest;
    const stripeRestricted = stripeRestrictedTest;
    const signerPrivate = process.env.SIGNER_PRIVATE;
    
    if('account' in request) {
        request.account = request.account.toLowerCase();
    }

    const web3 = new Web3(chains[request.chainId].rpc);
    const contract = new web3.eth.Contract(abi, chains[request.chainId].VerificationV2);
    
    const accountRecords = await loadAccount(request.account);
    const chainRecords = accountRecords[request.chainId] || [];
    let existingRow, verificationSession, feePaidBlock;
    
    async function updateRow(newData, chain = request.chainId) {
        const newRow = {
            ...(existingRow || {}),
            ...newData
        };
        
        await s3.upload({
            Bucket,
            Key: `${request.account}/${chain}/${feePaidBlock}.json`,
            Body: JSON.stringify(newRow),
        }).promise();
        
        existingRow = newRow;
    }

    switch(event.requestContext.http.path) {
        case '/verify': {
            feePaidBlock = String(await contract.methods.feePaidBlock(request.account).call());
            if(feePaidBlock === '0') return {
                statusCode: 400,
                body: JSON.stringify({ error: 'Must pay fee first' }),
            };

            const registerNonce = await noncer(request);
            if(registerNonce === null) return {
                statusCode: 400,
                body: JSON.stringify({ error: 'Nonce not unique' }),
            };
            const recovered = web3.eth.accounts.recover('Paid Fee on Block #' + feePaidBlock + '\n\n' + request.nonce, request.signature).toLowerCase();
            if(recovered !== request.account) return {
                statusCode: 400,
                body: JSON.stringify({ error: 'Invalid signature provided' }),
            };
            await registerNonce();
            
            if(chainRecords) {
                existingRow = chainRecords.find(row => row.feePaidBlock == feePaidBlock);
                if(existingRow) {
                    existingRow = await existingRow.fetch();
                    verificationSession = await stripe.identity.verificationSessions.retrieve(
                        existingRow.vsid
                    );
                    if(existingRow.vsstatus !== verificationSession.status) {
                        await updateRow({ vsstatus: verificationSession.status });
                    }
                    
                }
            }
            
            if(!existingRow) {
                if(process.env.MAX_VERIFICATIONS) {
                    const verificationCount = await s3BucketCount({ Bucket });
                    if(verificationCount >= Number(process.env.MAX_VERIFICATIONS)) return {
                        statusCode: 503,
                        body: JSON.stringify({ error: 'Verification limit reached' }),
                    };
                }

                // Create new verification session and return the url to the client
                verificationSession = await stripe.identity.verificationSessions.create({
                    type: 'document',
                        metadata: {
                        account: recovered,
                    },
                    options: {
                        document: {
                            allowed_types: [ 'passport' ],
                            require_live_capture: true,
                            require_matching_selfie: true,
                        },
                    },
                    return_url,
                });
                
                await updateRow({ vsid: verificationSession.id, feePaidBlock });

            } else if(existingRow.vsstatus !== 'requires_input') {
                return {
                    statusCode: 400,
                    body: JSON.stringify({ error: 'Verification already completed' }),
                };
            }

            return {
                statusCode: 200,
                body: JSON.stringify({ redirect: verificationSession.url }),
            };
        }
        case '/account-status': {
            let newest, feePaidChain;
            for(const chain of Object.keys(accountRecords)) {
                const row = accountRecords[chain][0]; // Sorted newest first
                if(!newest || row.lastModified > newest.lastModified) {
                    newest = row;
                    feePaidChain = chain;
                }
            }
            if(newest) {
                existingRow = await newest.fetch();
                feePaidBlock = existingRow.feePaidBlock;
            }
            
            let verificationAllowed = true;
            if(process.env.MAX_VERIFICATIONS) {
                const verificationCount = await s3BucketCount({ Bucket });
                if(verificationCount >= Number(process.env.MAX_VERIFICATIONS))
                    verificationAllowed = false;
            }
            
            const out = {
              verificationAllowed,
              status: null,
              exists: !!existingRow,
              signature: null,
              expiration: null,
              idHash: null,
              feePaidChain: null,
              feePaidBlock: null,
            };
            if(!out.exists) return out;
            out.redacted = existingRow.redacted;
            out.feePaidBlock = Number(existingRow.feePaidBlock);
            out.feePaidChain = feePaidChain;
            out.status = existingRow.vsstatus;
    
            if(out.status === 'verified' && existingRow.vsreport) {
              // This data is not sensitive
              out.expiration = Number(existingRow.expiration);
              out.idHash = await saltHash(web3, existingRow.idHash);
              const hash = web3.utils.keccak256(web3.eth.abi.encodeParameters(
                [ 'address', 'uint256', 'bytes32' ],
                [ request.account,
                  out.expiration,
                  out.idHash ]
              ));
              out.signature = web3.eth.accounts.sign(hash, '0x' + signerPrivate).signature;

              return out;
            } else if(out.status !== 'canceled') {
              // rate limiting for this query since it's on a public POST route
            //   if(account in accountReqRateLimit) {
            //     return out;
            //   } else {
            //     accountReqRateLimit[account] = true;
            //     setTimeout(() => {
            //       delete accountReqRateLimit[account];
            //     }, REQ_RATE_TIMEOUT);
            //   }
              const verificationSession =
                await stripe.identity.verificationSessions.retrieve(existingRow.vsid);
              out.status = verificationSession.status;
    
              if(verificationSession.status === 'verified') {
                const verificationReport = await stripeRestricted.identity.verificationReports.retrieve(
                  verificationSession.last_verification_report,
                  { expand: [
                      'document.expiration_date',
                      'document.number'
                    ] }
                );

                const expirationDate = new Date(
                  verificationReport.document.expiration_date.year,
                  verificationReport.document.expiration_date.month - 1,
                  verificationReport.document.expiration_date.day
                );
                out.expiration = Math.floor(expirationDate.getTime() / 1000);
                // discrete expirations every 2 weeks (in seconds) for better privacy
                out.expiration = out.expiration - (out.expiration % 1209600);
                const rawidHash = web3.utils.keccak256(
                  verificationReport.document.issuing_country +
                  verificationReport.document.number +
                  expirationDate.getTime().toString(10)
                );
                out.idHash = await saltHash(web3, rawidHash);
                const hash = web3.utils.keccak256(web3.eth.abi.encodeParameters(
                  [ 'address', 'uint256', 'bytes32' ],
                  [ request.account,
                    out.expiration,
                    out.idHash ]
                ));
                out.signature = web3.eth.accounts.sign(hash, signerPrivate).signature;

                await updateRow({
                    vsstatus: verificationSession.status,
                    vsreport: verificationSession.last_verification_report,
                    expiration: out.expiration,
                    idHash: rawidHash
                });
                
                // We've got what we need
                await stripe.identity.verificationSessions.redact(existingRow.vsid);
                
              } else if(verificationSession.status !== existingRow.vsstatus) {
                await updateRow({
                    vsstatus: verificationSession.status,
                });
              }
              return out;
            }
        }

    }

    return {
        statusCode: 404,
        body: JSON.stringify({
            error: 'Not found'
        }),
    };
};

function buffer2bits(buff) {
    const res = [];
    for (let i=0; i<buff.length; i++) {
        for (let j=0; j<8; j++) {
            if ((buff[i]>>j)&1) {
                res.push('1');
            } else {
                res.push('0');
            }
        }
    }
    return res;
}


async function noncer(request) {
    try {
        await s3.getObject(({
            Bucket,
            Key: `nonces/${request.nonce}.json`,
        })).promise();
    } catch(error) {
        // Return function that will register nonce as used
        return () => s3.upload({
            Bucket,
            Key: `nonces/${request.nonce}.json`,
            Body: JSON.stringify({ account: request.account, time: Date.now()}),
        }).promise();
    }
    // Nonce has been used
    return null;
}

async function loadAccount(account) {
    return (await s3.listObjectsV2({
        Bucket,
        Prefix: `${account}/`,
    }).promise()).Contents.sort((a, b) => {
        // Newest verification first
        const dateA = new Date(a.LastModified);
        const dateB = new Date(b.LastModified);
        return dateA > dateB ? -1 : dateB > dateA ? 1 : 0;
    }).reduce((out, cur) => {
        const keyParts = cur.Key.split('/');
        if(!(keyParts[1] in out)) out[keyParts[1]] = [];
        out[keyParts[1]].push({
            feePaidBlock: keyParts[2].replace('.json', ''),
            lastModified: new Date(cur.LastModified),
            fetch: async () => JSON.parse((await s3.getObject({ Bucket, Key: cur.Key }).promise()).Body.toString('utf-8')),
        });
        return out;
    }, {});
}

// This function written by ChatGPT4
async function s3BucketCount(params, objectCount = 0) {
    const response = await s3.listObjectsV2(params).promise();
    const objects = response.Contents;
    objectCount += objects.length;
    
    if (response.IsTruncated) {
        const newParams = {
            ...params,
            ContinuationToken: response.NextContinuationToken,
        };
        return await s3BucketCount(newParams, objectCount);
    }
    
    return objectCount;
}


async function saltHash(web3, idHash) {
    let salt;
    try {
        const saltObj = await s3.getObject({ Bucket, Key: `salt/${idHash}.json` }).promise();
        salt = JSON.parse(saltObj.Body.toString('utf8')).salt;
    } catch(error) {
        // Salt doesn't exist yet
    }
    if(!salt) {
        // Generate new salt
        salt = '0x' + randomBytes(32).toString('hex');
        await s3.upload({
            Bucket,
            Key: `salt/${idHash}.json`,
            Body: JSON.stringify({ salt }),
        }).promise();
    }
    return web3.utils.keccak256(web3.eth.abi.encodeParameters(
        [ 'bytes32', 'bytes32' ], [ idHash, salt ]));
}
