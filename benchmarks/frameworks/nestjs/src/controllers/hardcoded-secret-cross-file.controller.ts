import { Controller, Get } from '@nestjs/common';
import { ListObjectsV2Command, S3Client } from '@aws-sdk/client-s3';
import { awsConfig } from '../lib/hardcoded-secret-cross-file';

const s3 = new S3Client(awsConfig);

@Controller('api/hardcoded-secret-cross-file')
export class HardcodedSecretCrossFileController {
  @Get()
  async listReports() {
    const result = await s3.send(new ListObjectsV2Command({ Bucket: 'acme-reports' }));
    return (result.Contents ?? []).map((object) => object.Key);
  }
}
