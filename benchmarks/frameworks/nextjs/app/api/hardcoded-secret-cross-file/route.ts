import { ListObjectsV2Command, S3Client } from '@aws-sdk/client-s3';
import { NextResponse } from 'next/server';
import { awsConfig } from '@/lib/hardcoded-secret-cross-file';

const s3 = new S3Client(awsConfig);

export async function GET() {
  const result = await s3.send(new ListObjectsV2Command({ Bucket: 'acme-reports' }));
  return NextResponse.json((result.Contents ?? []).map((object) => object.Key));
}
