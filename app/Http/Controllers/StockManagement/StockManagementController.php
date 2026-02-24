<?php

namespace App\Http\Controllers\StockManagement;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\StockManagement as StockManagementModel;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class StockManagementController extends Controller
{
    public function index(Request $request)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:255'],
        ]);

        $query = StockManagementModel::query();
        $search = trim((string) ($validated['search'] ?? ''));

        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('item_name', 'like', '%' . $search . '%')
                    ->orWhere('description', 'like', '%' . $search . '%')
                    ->orWhere('unit', 'like', '%' . $search . '%')
                    ->orWhere('quantity', 'like', '%' . $search . '%')
                    ->orWhere('price', 'like', '%' . $search . '%')
                    ->orWhere('total_price', 'like', '%' . $search . '%');
            });
        }

        $stocks = $query->latest()->paginate(10);

        return response()->json([
            'status' => true,
            'message' => 'Stock items fetched successfully.',
            'data' => $stocks->items(),
            'pagination' => [
                'current_page' => $stocks->currentPage(),
                'last_page' => $stocks->lastPage(),
                'per_page' => $stocks->perPage(),
                'total' => $stocks->total(),
            ],
        ]);
    }

    public function store(Request $request)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'item_name' => ['required', 'string', 'max:255'],
            'description' => ['required', 'string'],
            'quantity' => ['required', 'integer', 'min:0'],
            'price' => ['required', 'numeric', 'min:0'],
            'unit' => ['nullable', 'string', 'max:100'],
        ]);

        $stock = new StockManagementModel();
        $stock->item_name = $validated['item_name'];
        $stock->description = $validated['description'];
        $stock->quantity = $validated['quantity'];
        $stock->price = $validated['price'];
        $stock->unit = $validated['unit'] ?? null;
        $stock->total_price = round(((float) $validated['quantity']) * ((float) $validated['price']), 2);
        $stock->save();

        return response()->json([
            'status' => true,
            'message' => 'Stock item created successfully.',
            'data' => $stock,
        ], 201);
    }

    public function show(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin token is required.',
            ], 401);
        }

        $stock = StockManagementModel::find($id);
        if (!$stock) {
            return response()->json([
                'status' => false,
                'message' => 'Stock item not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Stock item fetched successfully.',
            'data' => $stock,
        ]);
    }

    public function update(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin token is required.',
            ], 401);
        }

        $stock = StockManagementModel::find($id);
        if (!$stock) {
            return response()->json([
                'status' => false,
                'message' => 'Stock item not found.',
            ], 404);
        }

        $validated = $request->validate([
            'item_name' => ['sometimes', 'required', 'string', 'max:255'],
            'description' => ['sometimes', 'required', 'string'],
            'quantity' => ['sometimes', 'required', 'integer', 'min:0'],
            'price' => ['sometimes', 'required', 'numeric', 'min:0'],
            'unit' => ['nullable', 'string', 'max:100'],
        ]);

        if (array_key_exists('item_name', $validated)) {
            $stock->item_name = $validated['item_name'];
        }
        if (array_key_exists('description', $validated)) {
            $stock->description = $validated['description'];
        }
        if (array_key_exists('quantity', $validated)) {
            $stock->quantity = $validated['quantity'];
        }
        if (array_key_exists('price', $validated)) {
            $stock->price = $validated['price'];
        }
        if (array_key_exists('unit', $validated)) {
            $stock->unit = $validated['unit'];
        }

        $stock->total_price = round(((float) $stock->quantity) * ((float) $stock->price), 2);
        $stock->save();

        return response()->json([
            'status' => true,
            'message' => 'Stock item updated successfully.',
            'data' => $stock,
        ]);
    }

    public function destroy(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin token is required.',
            ], 401);
        }

        $stock = StockManagementModel::find($id);
        if (!$stock) {
            return response()->json([
                'status' => false,
                'message' => 'Stock item not found.',
            ], 404);
        }

        $stock->delete();

        return response()->json([
            'status' => true,
            'message' => 'Stock item deleted successfully.',
        ]);
    }

    private function authenticatedAdminFromToken(Request $request): ?Admin
    {
        $token = $request->bearerToken();
        if (!$token) {
            return null;
        }

        $payload = $this->decodeJwtToken($token);
        if (!$payload) {
            return null;
        }

        if (($payload['role'] ?? null) !== 'admin') {
            return null;
        }

        $adminId = (int) ($payload['sub'] ?? 0);
        if ($adminId <= 0) {
            return null;
        }

        return Admin::find($adminId);
    }

    private function decodeJwtToken(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;
        $signature = $this->base64UrlDecode($encodedSignature);
        if ($signature === false) {
            return null;
        }

        $expectedSignature = hash_hmac('sha256', $encodedHeader . '.' . $encodedPayload, $this->jwtSecret(), true);
        if (!hash_equals($expectedSignature, $signature)) {
            return null;
        }

        $payloadJson = $this->base64UrlDecode($encodedPayload);
        if ($payloadJson === false) {
            return null;
        }

        $payload = json_decode($payloadJson, true);
        if (!is_array($payload)) {
            return null;
        }

        $blacklistKey = 'admin_jwt_blacklist:' . hash('sha256', $token);
        if (Cache::has($blacklistKey)) {
            return null;
        }

        return $payload;
    }

    private function jwtSecret(): string
    {
        $secret = env('JWT_SECRET');
        if (!empty($secret)) {
            return $secret;
        }

        $appKey = (string) config('app.key', '');
        if (str_starts_with($appKey, 'base64:')) {
            $decoded = base64_decode(substr($appKey, 7), true);
            if ($decoded !== false) {
                return $decoded;
            }
        }

        return $appKey;
    }

    private function base64UrlDecode(string $value): string|false
    {
        $remainder = strlen($value) % 4;
        if ($remainder) {
            $value .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($value, '-_', '+/'), true);
    }
}
