<?php

namespace App\Http\Controllers\Expense;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Expenses;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class ExpenseController extends Controller
{
    public function index(Request $request)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized.',
            ], 401);
        }

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:255'],
            'period' => ['nullable', 'in:daily,weekly,monthly,yearly'],
        ]);

        $query = Expenses::with('creator');
        $search = trim((string) ($validated['search'] ?? ''));
        $period = $validated['period'] ?? null;

        if (!empty($period)) {
            $now = now();

            if ($period === 'daily') {
                $query->whereDate('date', $now->toDateString());
            } elseif ($period === 'weekly') {
                $query->whereBetween('date', [
                    $now->copy()->startOfWeek()->toDateString(),
                    $now->copy()->endOfWeek()->toDateString(),
                ]);
            } elseif ($period === 'monthly') {
                $query->whereYear('date', $now->year)
                    ->whereMonth('date', $now->month);
            } elseif ($period === 'yearly') {
                $query->whereYear('date', $now->year);
            }
        }

        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('title', 'like', '%' . $search . '%')
                    ->orWhere('category', 'like', '%' . $search . '%')
                    ->orWhere('amount', 'like', '%' . $search . '%')
                    ->orWhere('date', 'like', '%' . $search . '%')
                    ->orWhereHas('creator', function ($creatorQuery) use ($search) {
                        $creatorQuery->where('full_name', 'like', '%' . $search . '%')
                            ->orWhere('email', 'like', '%' . $search . '%');
                    });
            });
        }

        $expenses = $query->latest()->paginate(10);
        $expenses->getCollection()->transform(fn (Expenses $expense) => $this->transformExpense($expense));

        return response()->json([
            'status' => true,
            'message' => 'Expenses fetched successfully.',
            'data' => $expenses->items(),
            'pagination' => [
                'current_page' => $expenses->currentPage(),
                'last_page' => $expenses->lastPage(),
                'per_page' => $expenses->perPage(),
                'total' => $expenses->total(),
            ],
        ]);
    }

    public function store(Request $request)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized.',
            ], 401);
        }

        $validated = $request->validate([
            'title' => ['required', 'string', 'max:255'],
            'category' => ['required', 'string', 'max:255'],
            'amount' => ['required', 'numeric', 'min:0'],
            'date' => ['required', 'date'],
        ]);

        $expense = new Expenses();
        $expense->title = $validated['title'];
        $expense->category = $validated['category'];
        $expense->amount = $validated['amount'];
        $expense->date = $validated['date'];
        $expense->created_by = $admin->id;
        $expense->save();
        $expense->load('creator');

        return response()->json([
            'status' => true,
            'message' => 'Expense created successfully.',
            'data' => $this->transformExpense($expense),
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

        $expense = Expenses::with('creator')->find($id);
        if (!$expense) {
            return response()->json([
                'status' => false,
                'message' => 'Expense not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Expense fetched successfully.',
            'data' => $this->transformExpense($expense),
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

        $expense = Expenses::find($id);
        if (!$expense) {
            return response()->json([
                'status' => false,
                'message' => 'Expense not found.',
            ], 404);
        }

        $validated = $request->validate([
            'title' => ['sometimes', 'required', 'string', 'max:255'],
            'category' => ['sometimes', 'required', 'string', 'max:255'],
            'amount' => ['sometimes', 'required', 'numeric', 'min:0'],
            'date' => ['sometimes', 'required', 'date'],
        ]);

        if (array_key_exists('title', $validated)) {
            $expense->title = $validated['title'];
        }

        if (array_key_exists('category', $validated)) {
            $expense->category = $validated['category'];
        }

        if (array_key_exists('amount', $validated)) {
            $expense->amount = $validated['amount'];
        }

        if (array_key_exists('date', $validated)) {
            $expense->date = $validated['date'];
        }

        $expense->save();
        $expense->load('creator');

        return response()->json([
            'status' => true,
            'message' => 'Expense updated successfully.',
            'data' => $this->transformExpense($expense),
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

        $expense = Expenses::find($id);
        if (!$expense) {
            return response()->json([
                'status' => false,
                'message' => 'Expense not found.',
            ], 404);
        }

        $expense->delete();

        return response()->json([
            'status' => true,
            'message' => 'Expense deleted successfully.',
        ]);
    }

    private function transformExpense(Expenses $expense): array
    {
        $data = $expense->toArray();
        $data['creator'] = $expense->creator ? [
            'id' => $expense->creator->id,
            'full_name' => $expense->creator->full_name,
            'email' => $expense->creator->email,
            'role' => $expense->creator->role,
        ] : null;

        return $data;
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
