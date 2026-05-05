import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {

  constructor() {
    const adapter = new PrismaPg({
      connectionString: process.env.DATABASE_URL,
    });

    super({
      adapter,
      log:['query','error']
      //comments: [queryTags(), traceContext()],
      //👆
      //https://www.prisma.io/docs/orm/reference/prisma-client-reference
      /*
      Prisma Query Extensions used for Observability.
      enabling End-to-End Tracing.

      @prisma/sqlcommenter-query-tags
      Adds arbitrary tags to queries within an async context using AsyncLocalStorage
      
      @prisma/sqlcommenter-trace-context
      Adds W3C Trace Context (traceparent) headers for distributed tracing
      */
    });
  }
  
  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}