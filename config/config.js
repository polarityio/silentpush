module.exports = {
  polarityIntegrationUuid: '3133dc50-63ca-11ee-9f00-b7a8aebacae2',
  name: 'Silent Push',
  acronym: 'SP',
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: ''
  },
  logging: { level: 'info' },
  description:
    'Enrich alerts with Whois, Risk Scores, and much more context from Silent Push Threat Intelligence',
  defaultColor: 'dark-blue-gray',
  entityTypes: ['IPv4', 'IPv6', 'domain', 'url'],
  styles: ['./styles/main.css'],
  block: {
    component: {
      file: './components/component.js'
    },
    template: {
      file: './templates/template.hbs'
    }
  },
  options: [
    {
      key: 'url',
      name: 'Silent Push API URL',
      description: 'The API URL for your Silent Push instance.  Defaults to "https://app.silentpush.com/api".',
      default: 'https://app.silentpush.com/api',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'apiKey',
      name: 'API Key',
      description:
        "If you don't have an api key yet, sign up on https://explore.silentpush.com/register",
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
    }
  ]
};
