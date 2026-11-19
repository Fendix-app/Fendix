import { ListObjectsV2Command, S3Client } from '@aws-sdk/client-s3';
import { NextResponse } from 'next/server';

const AWS_ACCESS_KEY_ID = '__EVAL_AWS_ACCESS_KEY_ID__';
const AWS_SECRET_ACCESS_KEY = '__EVAL_AWS_SECRET_ACCESS_KEY__'; // EVAL-SINK

const s3 = new S3Client({
  region: 'us-east-1',
  credentials: { accessKeyId: AWS_ACCESS_KEY_ID, secretAccessKey: AWS_SECRET_ACCESS_KEY },
});

export async function GET() {
  const result = await s3.send(new ListObjectsV2Command({ Bucket: 'acme-reports' }));
  return NextResponse.json((result.Contents ?? []).map((object) => object.Key));
}
