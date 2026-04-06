<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\RefreshToken;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    // POST /api/auth/register
    // Body: { name, email, password }
    // Response 201: { user:{id,name,email}, access_token, refresh_token, token_type:"bearer" }
    public function register(Request $request): JsonResponse
    {
        $data = $request->validate([
            'name'     => ['required', 'string', 'max:255'],
            'email'    => ['required', 'email', 'unique:users,email'],
            'password' => ['required', 'string', 'min:6'],
        ]);

        $user = User::create([
            'name'     => $data['name'],
            'email'    => $data['email'],
            'password' => Hash::make($data['password']),
        ]);

        return response()->json($this->issueTokens($user), 201);
    }

    // POST /api/auth/login
    // Body: { email, password }
    // Response 200: { user:{id,name,email}, access_token, refresh_token, token_type:"bearer" }
    // Error 401: { message: "Invalid credentials" }
    public function login(Request $request): JsonResponse
    {
        $data = $request->validate([
            'email'    => ['required', 'email'],
            'password' => ['required', 'string'],
        ]);

        $user = User::where('email', $data['email'])->first();

        if (!$user || !Hash::check($data['password'], $user->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        return response()->json($this->issueTokens($user));
    }

    // POST /api/auth/refresh
    // Body: { refresh_token: "<opaque string>" }
    // Response 200: { user:{id,name,email}, access_token, refresh_token, token_type:"bearer" }
    // Error 401: { message: "Invalid or expired refresh token" }
    public function refresh(Request $request): JsonResponse
    {
        $request->validate(['refresh_token' => ['required', 'string']]);

        $record = RefreshToken::where('token', $request->refresh_token)->first();

        if (!$record || $record->isExpired()) {
            $record?->delete();
            return response()->json(['message' => 'Invalid or expired refresh token'], 401);
        }

        $user = $record->user;

        // Rotate: delete old record, issue fresh pair - read about refresh_token_rotation
        $record->delete();

        return response()->json($this->issueTokens($user));
    }

    // POST /api/auth/logout
    // Header: Authorization: Bearer <access_token>
    // Body: { refresh_token: "<opaque string>" } (optional)
    // Response 200: { message: "Logged out" }
    public function logout(Request $request): JsonResponse
    {
        // Invalidate the JWT on the blocklist (tymon handles via cache)
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
        } catch (\Exception) {
            // Token already expired — fine
        }

        // Delete only the current device's refresh token (per-device logout)
        RefreshToken::where('token', $request->input('refresh_token'))->delete();

        // Delete all refresh tokens for this user (full session revocation — logout from all devices)
        // if ($request->user()) {
        //     $request->user()->refreshTokens()->delete();
        // }

        return response()->json(['message' => 'Logged out']);
    }

    // GET /api/auth/me
    // Header: Authorization: Bearer <access_token>
    // Response 200: { id, name, email }
    public function me(Request $request): JsonResponse
    {
        $user = $request->user();
        return response()->json([
            'id'    => $user->id,
            'name'  => $user->name,
            'email' => $user->email,
        ]);
    }

    // Generate a new JWT access token + opaque refresh token and persist the refresh token
    private function issueTokens(User $user): array
    {
        $accessToken  = JWTAuth::fromUser($user);
        $refreshToken = Str::random(80);

        RefreshToken::create([
            'user_id'    => $user->id,
            'token'      => $refreshToken,
            'expires_at' => now()->addDays(7),
        ]);

        return [
            'user'          => ['id' => $user->id, 'name' => $user->name, 'email' => $user->email],
            'access_token'  => $accessToken,
            'refresh_token' => $refreshToken,
            'token_type'    => 'bearer',
        ];
    }
}
