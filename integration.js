const request = require('postman-request');
const async = require('async');

let Logger;
let apiKey = '';

function startup(logger) {
  Logger = logger;
}

doLookup = (entities, options, cb) => {
  Logger.trace({ entities }, 'doLookup entities');
  apiKey = options.apiKey;
  let lookupResults = [];
  async.each(
    entities,
    function (entity, next) {
      if (entity.isIPv4) {
        enrichIPv4(entity, options, function (err, result) {
          if (!err) {
            lookupResults.push(result); // add to our results if there was no error
          }
          next(err); // processing complete
        });
      } else if (entity.isDomain) {
        enrichDomain(entity, options, function (err, result) {
          if (!err) {
            lookupResults.push(result);
          }
          next(err);
        });
      } else if (entity.isURL) {
        parseIoC(entity.value, options, function (err, parsedIoC) {
          if (err) {
            return next(err);
          }
          Logger.trace(`parsedIoC: ${parsedIoC}`);
          entity.value = parsedIoC;
          enrichDomain(entity, options, (err, result) => {
            if (!err) {
              lookupResults.push(result); // add to our results if there was no error
            } else {
              enrichIPv4(entity, options, (err, result) => {
                if (!err) {
                  lookupResults.push(result);
                }
                next(err);
              });
            }
            next(err);
          });
        });
      } else {
        next(null);
      }
    },
    function (err) {
      if (err) {
        Logger.error({ err }, 'doLookup error');
      }
      Logger.trace({ lookupResults }, 'lookupResults');
      cb(err, lookupResults);
    }
  );
};

enrichIPv4 = (entity, options, done) => {
  request(getEnrichmentURI(entity, 'ipv4', options), function (err, response, body) {
    Logger.trace({ body }, `enrichIPv4 body`);

    if (err || response.statusCode !== 200) {
      Logger.error(
        { err, statusCode: response ? response.statusCode : 'NA' },
        'enrichIPv4 error'
      );

      // return either the error object, or the body as an error
      done(err || body);
      return;
    }
    // there was no error in making the GET request so process the body here
    done(null, {
      entity: entity,
      data: {
        summary: summary(body.response),
        details: body.response
      }
    });
  });
};

enrichDomain = (entity, options, done) => {
  request(getEnrichmentURI(entity, 'domain', options), function (err, response, body) {
    Logger.trace({ body }, 'enrichDomain body');

    if (err || response.statusCode !== 200) {
      Logger.error(
        { err, statusCode: response ? response.statusCode : 'NA' },
        'enrichDomain error'
      );
      done(err || body);
      return;
    }

    done(null, {
      entity: entity,
      data: {
        summary: summary(body.response),
        details: {
          domainData: body.response
        }
      }
    });
  });
};

getEnrichmentURI = (entity, type = 'ipv4', options) => {
  const enrichment_url =
    'https://app.silentpush.com/api' +
    `/v1/merge-api/explore/enrich/${type}/${entity.value}` +
    '?explain=1&scan_data=1&with_metadata=1&query_type=Enrichment&' +
    'query_origin=ENRICHMENT&is_voluntary=1';
  return {
    url: enrichment_url,
    json: true,
    // verify: false,
    headers: {
      'X-Api-Key': apiKey,
      'User-Agent': 'PolarityIO'
    }
  };
};

parseIoC = (ioc, options, done) => {
  const uri = {
    url: options.url + '/v2/utils/parse-ioc/',
    body: { ioc: ioc },
    json: true,
    // verify: false,
    headers: {
      'X-Api-Key': apiKey,
      'User-Agent': 'PolarityIO'
    }
  };

  request.post(uri, function (err, response, body) {
    if (err) {
      Logger.error({ err }, 'parseIoC error');
      return done(err);
    }

    Logger.trace({ body }, 'parseIoC body');

    done(null, body.result);
  });
};

function summary(response) {
  const tags = [];

  if (response && response.ip2asn && response.ip2asn.length > 0) {
    for (const ip of response.ip2asn) {
      tags.push(`ASN: ${ip.asn}`);
      tags.push(`SP Risk Score: ${ip.sp_risk_score}`);
      tags.push(`Subnet: ${ip.subnet}`);
    }
  }

  if (response && response.domain_string_frequency_probability) {
    tags.push(`SP Risk Score: ${response.sp_risk_score}`);
    if (response && response.domaininfo.whois_age) {
      tags.push(`WhoIs Age: ${response.domaininfo.whois_age}`);
    }

    if (response && response.domaininfo.registrar) {
      tags.push(`Registrar: ${response.domaininfo.registrar}`);
    }
  }

  return tags;
}

function validateOptions(userOptions, cb) {
  const errors = [];

  if (
      typeof userOptions.url.value !== 'string' ||
      (typeof userOptions.url.value === 'string' &&
          userOptions.url.value.length === 0)
  ) {
    errors.push({
      key: 'url',
      message: 'You must provide a valid Silent Push API URL'
    });
  }

  if (
    typeof userOptions.apiKey.value !== 'string' ||
    (typeof userOptions.apiKey.value === 'string' &&
      userOptions.apiKey.value.length === 0)
  ) {
    errors.push({
      key: 'apiKey',
      message: 'You must provide a valid API Key'
    });
  }

  cb(null, errors);
}

module.exports = {
  startup: startup,
  validateOptions: validateOptions,
  doLookup: doLookup
};
