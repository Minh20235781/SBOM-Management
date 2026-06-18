declare module 'swagger-jsdoc' {
  type SwaggerJsdocOptions = {
    definition: Record<string, unknown>;
    apis: string[];
  };

  function swaggerJSDoc(options: SwaggerJsdocOptions): Record<string, unknown>;
  export default swaggerJSDoc;
}

declare module 'swagger-ui-express' {
  import { RequestHandler } from 'express';

  export const serve: RequestHandler[];
  export function setup(swaggerDoc: Record<string, unknown>): RequestHandler;
}
