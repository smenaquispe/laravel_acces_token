<?php
namespace Tests\Unit;
use Tests\TestCase;


class ValidateAuthTokenMiddleware extends TestCase
{
    /**
     * A basic test example.
     *
     * @return void
     */
    public function test_token_not_provided()
    {
        $response = $this->getJson('/api/protected'); // Assume the middleware is applied to this route
        
        $response->assertStatus(401)
                 ->assertJson(['error' => 'Token not provided']);
    }

    public function test_it_passes_through_when_valid_token_is_provided()
    {
        $validToken = env("AUTH0_TEST_TOKEN"); // Insert a valid token from Auth0
        
        $response = $this->withHeaders([
            'Authorization' => 'Bearer ' . $validToken,
        ])->getJson('/api/protected');
        
        $response->assertStatus(200); // Assuming this route returns 200 on success
    }
    
}
