import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // 全局 validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,       
      forbidNonWhitelisted: true,
      transform: true,       
    }),
  );

  app.use(cookieParser());
  // CORS
  app.enableCors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true,
  });

  //all route have api/...
  app.setGlobalPrefix('api');
  
  await app.listen(process.env.PORT ?? 3000);
  console.log(`Application is running on: ${await app.getUrl()}`);
}
bootstrap();
