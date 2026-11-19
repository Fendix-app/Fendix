const AWS_ACCESS_KEY_ID = '__EVAL_AWS_ACCESS_KEY_ID__';
const AWS_SECRET_ACCESS_KEY = '__EVAL_AWS_SECRET_ACCESS_KEY__'; // EVAL-SINK

const awsConfig = {
  region: 'us-east-1',
  credentials: { accessKeyId: AWS_ACCESS_KEY_ID, secretAccessKey: AWS_SECRET_ACCESS_KEY },
};

module.exports = { awsConfig };
