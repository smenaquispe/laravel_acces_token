<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Auth0\SDK\Auth0;
use Auth0\SDK\Configuration\SdkConfiguration;
use Auth0\SDK\Token;
use Symfony\Component\HttpFoundation\Response;


class ValidateAuthToken
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->bearerToken();
        if (!$token) {
            return response()->json(['error' => 'Token not provided'], Response::HTTP_UNAUTHORIZED);
        }

        $config = new SdkConfiguration(
            strategy: SdkConfiguration::STRATEGY_API,
            domain: env('AUTH0_DOMAIN'),
            audience: [env('AUTH0_AUDIENCE')],
            tokenJwksUri: env('AUTH0_TOKEN_JWKS_URI'),
        );
        
        try {
            $auth0 = new Auth0($config);
            $auth0->decode($token, tokenType: Token::TYPE_ACCESS_TOKEN);
            
            return $next($request);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Invalid token: ' . $e->getMessage()], Response::HTTP_UNAUTHORIZED);
        }
    }

}

