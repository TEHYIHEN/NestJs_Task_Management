import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const CurrentUser = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return data ? request.user?.[data] : request.user;
  },
);

// 1. createParamDecorator
// What it is: A factory function provided by NestJS used specifically to generate your 
// own custom route parameter decorators.

// Why use it: While NestJS provides built-in decorators like @Body() or @Req(), you often need to extract deep, 
// specific data repeatedly (like the logged-in user). createParamDecorator lets you encapsulate 
// this logic into a clean, reusable decorator like @CurrentUser().

// How it works: It takes a callback function with two arguments:

// data: The argument passed to the decorator when used (e.g., in @CurrentUser('id'), data is 'id').

// ctx: The execution context (see ExecutionContext below).

// 2. ctx.switchToHttp()
// What it is: ctx is an instance of ExecutionContext, which contains all the metadata regarding the current execution pipeline.

// Why use it: NestJS is designed to be agnostic—meaning it can handle standard HTTP requests, WebSockets, GraphQL, or RPC (Microservices).

// What it does: Since NestJS doesn't know the protocol context upfront, ctx.switchToHttp() explicitly tells the framework: "I am currently operating within an HTTP application. Please switch the context so I can access HTTP-specific utilities."

// 3. getRequest()
// What it is: A method available on the HTTP arguments host after calling switchToHttp().

// What it does: It extracts the native, underlying HTTP Request object (typically the Express or Fastify request object).

// Where request.user comes from: In a standard authentication flow, an authentication Guard (like Passport.js or a custom JWT Guard) validates the token and attaches the authenticated user's payload to the request object as request.user.