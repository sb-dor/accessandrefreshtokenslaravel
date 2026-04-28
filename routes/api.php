<?php

use App\Http\Controllers\Api\AuthController;
use Illuminate\Support\Facades\Route;

// Public endpoints — no authentication required
Route::post('/auth/register', [AuthController::class, 'register']);
Route::post('/auth/login',    [AuthController::class, 'login']);
Route::post('/auth/refresh',  [AuthController::class, 'refresh']);

// Protected endpoints — valid JWT required
Route::middleware('auth:api')->group(function () {
    Route::post('/auth/logout', [AuthController::class, 'logout']);
    Route::get('/auth/me',      [AuthController::class, 'me']);

    // Admin only
    Route::middleware('role:admin')->group(function () {
        Route::get('/admin/users',    fn() => response()->json(['message' => 'Admin: user list']));
        Route::delete('/admin/users/{id}', fn() => response()->json(['message' => 'Admin: user deleted']));
    });

    // Admin or Manager
    Route::middleware('role:admin,manager')->group(function () {
        Route::get('/reports', fn() => response()->json(['message' => 'Reports: accessible by admin and manager']));
    });

    // Admin, Manager or Cashier (all authenticated users)
    Route::middleware('role:admin,manager,cashier')->group(function () {
        Route::get('/sales', fn() => response()->json(['message' => 'Sales: accessible by all roles']));
    });
});
