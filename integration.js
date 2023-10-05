const request = require("postman-request");
const async = require("async");

require("dotenv").config();

let Logger;
let apiKey = "";
let SILENTPUSH_API_URL;

function startup(logger) {
  Logger = logger;
  SILENTPUSH_API_URL =
    process.env.SILENTPUSH_API_URL || "https://app.silentpush.com/api/";
}

doLookup = (entities, options, cb) => {
  Logger.info(entities);
  apiKey = options.apiKey;
  let lookupResults = [];
  async.each(
    entities,
    function (entity, next) {
      if (entity.isIPv4) {
        enrichIPv4(entity, function (err, result) {
          if (!err) {
            lookupResults.push(result); // add to our results if there was no error
          }
          next(err); // processing complete
        });
      } else if (entity.isDomain) {
        enrichDomain(entity, function (err, result) {
          if (!err) {
            lookupResults.push(result);
          }
          next(err);
        });
      } else if (entity.isURL) {
        parseIoC(entity.value, function (parsedIoC) {
          Logger.info(`parsedIoC: ${parsedIoC}`);
          entity.value = parsedIoC;
          enrichDomain(entity, (err, result) => {
            if (!err) {
              lookupResults.push(result); // add to our results if there was no error
            } else {
              enrichIPv4(entity, (err, result) => {
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
      Logger.trace({ lookupResults: lookupResults }, "lookupResults");
      cb(err, lookupResults);
    }
  );
};

enrichIPv4 = (entity, done) => {
  Logger.info(entity);
  request(getEnrichmentURI(entity), function (err, response, body) {
    Logger.info(`enrichIPv4 error: ${err}`);
    Logger.info(`enrichIPv4 response: ${JSON.stringify(response)}`);
    Logger.info(`enrichIPv4 body: ${JSON.stringify(body)}`);
    if (err || response.statusCode !== 200) {
      // return either the error object, or the body as an error
      done(err || body);
      return;
    }
    // there was no error in making the GET request so process the body here
    done(null, {
      entity: entity,
      data: {
        summary: summary(body.response),
        details: body.response,
      },
    });
  });
};

enrichDomain = (entity, done) => {
  Logger.info(entity);
  request(getEnrichmentURI(entity, "domain"), function (err, response, body) {
    Logger.info(`enrichDomain error: ${err}`);
    Logger.info(`enrichDomain response: ${JSON.stringify(response)}`);
    Logger.info(`enrichDomain body: ${JSON.stringify(body)}`);
    if (err || response.statusCode !== 200) {
      done(err || body);
      return;
    }
    done(null, {
      entity: entity,
      data: {
        summary: summary(body.response),
        details: {
          domainData: body.response,
        },
      },
    });
  });
};

getEnrichmentURI = (entity, type = "ipv4") => {
  const enrichment_url =
    SILENTPUSH_API_URL +
    `v1/merge-api/explore/enrich/${type}/${entity.value}` +
    "?explain=1&scan_data=1&with_metadata=1&query_type=Enrichment&" +
    "query_origin=ENRICHMENT&is_voluntary=1";
  return {
    url: enrichment_url,
    json: true,
    // verify: false,
    headers: {
      "X-Api-Key": apiKey,
      "User-Agent": "PolarityIO",
    },
  };
};

parseIoC = (ioc, done) => {
  const uri = {
    url: SILENTPUSH_API_URL + "v2/utils/parse-ioc/",
    body: { ioc: ioc },
    json: true,
    // verify: false,
    headers: {
      "X-Api-Key": apiKey,
      "User-Agent": "PolarityIO",
    },
  };
  request.post(uri, function (err, response, body) {
    Logger.info(`parseIoC error: ${err}`);
    Logger.info(`parseIoC response: ${JSON.stringify(response)}`);
    Logger.info(`parseIoC body: ${JSON.stringify(body)}`);
    done(body.result);
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
    if (response && response.domain_string_frequency_probability.whois_age) {
      tags.push(`WhoIs Age: ${response.domaininfo.whois_age}`);
    }

    if (response && response.domain_string_frequency_probability.registrar) {
      tags.push(`Registrar: ${response.domaininfo.registrar}`);
    }
  }

  return tags;
}

module.exports = {
  startup: startup,
  doLookup: doLookup,
};