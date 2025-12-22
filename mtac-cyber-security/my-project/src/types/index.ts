export interface Request {
    body: Record<string, any>;
    params: Record<string, string>;
    query: Record<string, string>;
}

export interface Response {
    status: (statusCode: number) => Response;
    json: (data: any) => void;
    send: (data: any) => void;
}