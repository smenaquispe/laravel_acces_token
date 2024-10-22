<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use Psy\Readline\Hoa\Console;

class ValidateAuthToken
{
   
    public function handle(Request $request, Closure $next)
    {
        // Obtener el token del encabezado Authorization
        $authHeader = $request->header('Authorization');
        if (!$authHeader) {
            return response()->json(['error' => 'Authorization header not found.'], 401);
        }

        // Eliminar "Bearer " del encabezado
        $jwt = str_replace('Bearer ', '', $authHeader);

        // Configura el dominio de Auth0
        $auth0Domain = env('AUTH0_DOMAIN');

        // Obtener las claves JWK
        $jwksUrl = "https://{$auth0Domain}/.well-known/jwks.json";
        $jwks = json_decode(file_get_contents($jwksUrl), true);

        try {
            // Obtener la clave de firma del JWK
            $key = JWK::parseKey($jwks['keys'][0]);

            // Decodificar y verificar el JWT
            $decoded = JWT::decode($jwt, $key);

            // Almacena el token decodificado en el request para uso posterior
            $request->attributes->add(['decoded' => $decoded]);

            return $next($request);
        } catch (ExpiredException $e) {
            return response()->json(['error' => 'Token has expired.'], 401);
        } catch (SignatureInvalidException $e) {
            return response()->json(['error' => 'Invalid token.'], 401);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Token could not be parsed.'], 401);
        }
   
    }

}

