<?php

namespace App\Http\Controllers\AssignStock;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\AssignStock;
use App\Models\Employee;
use App\Models\StockManagement;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class AssignStockController extends Controller
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
            'employee_id' => ['nullable', 'integer', 'exists:employees,id'],
            'stock_management_id' => ['nullable', 'integer', 'exists:stock_management,id'],
            'assign_date' => ['nullable', 'date'],
        ]);

        $query = AssignStock::query();

        if (!empty($validated['employee_id'])) {
            $query->where('employee_id', (int) $validated['employee_id']);
        }

        if (!empty($validated['stock_management_id'])) {
            $query->where('stock_management_id', (int) $validated['stock_management_id']);
        }

        if (!empty($validated['assign_date'])) {
            $query->whereDate('assign_date', $validated['assign_date']);
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $employeeIds = Employee::query()
                ->where('emp_name', 'like', '%' . $search . '%')
                ->orWhere('emp_email', 'like', '%' . $search . '%')
                ->pluck('id');

            $stockIds = StockManagement::query()
                ->where('item_name', 'like', '%' . $search . '%')
                ->pluck('id');

            $query->where(function ($builder) use ($search, $employeeIds, $stockIds) {
                $builder->where('remarks', 'like', '%' . $search . '%')
                    ->orWhere('assign_date', 'like', '%' . $search . '%')
                    ->orWhereIn('employee_id', $employeeIds)
                    ->orWhereIn('stock_management_id', $stockIds);
            });
        }

        $assignments = $query->latest()->paginate(10);
        $data = $this->transformAssignments($assignments->items());

        return response()->json([
            'status' => true,
            'message' => 'Assigned stocks fetched successfully.',
            'data' => $data,
            'pagination' => [
                'current_page' => $assignments->currentPage(),
                'last_page' => $assignments->lastPage(),
                'per_page' => $assignments->perPage(),
                'total' => $assignments->total(),
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
            'employee_id' => ['required', 'integer', 'exists:employees,id'],
            'stock_management_id' => ['required', 'integer', 'exists:stock_management,id'],
            'assign_quantity' => ['required', 'integer', 'min:1'],
            'assign_date' => ['required', 'date'],
            'remarks' => ['nullable', 'string'],
        ]);

        try {
            $assignment = DB::transaction(function () use ($validated) {
                $stock = StockManagement::where('id', $validated['stock_management_id'])
                    ->lockForUpdate()
                    ->first();

                if (!$stock) {
                    return null;
                }

                if ((int) $stock->quantity < (int) $validated['assign_quantity']) {
                    throw new \RuntimeException('Insufficient stock quantity.');
                }

                $assignment = new AssignStock();
                $assignment->employee_id = $validated['employee_id'];
                $assignment->stock_management_id = $validated['stock_management_id'];
                $assignment->assign_quantity = $validated['assign_quantity'];
                $assignment->assign_date = $validated['assign_date'];
                $assignment->remarks = $validated['remarks'] ?? null;
                $assignment->save();

                $stock->quantity = (int) $stock->quantity - (int) $validated['assign_quantity'];
                $stock->total_price = round(((float) $stock->quantity) * ((float) $stock->price), 2);
                $stock->save();

                return $assignment;
            });
        } catch (\RuntimeException $exception) {
            return response()->json([
                'status' => false,
                'message' => $exception->getMessage(),
            ], 422);
        }

        if (!$assignment) {
            return response()->json([
                'status' => false,
                'message' => 'Stock item not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Stock assigned successfully.',
            'data' => $this->transformAssignments([$assignment])[0],
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

        $assignment = AssignStock::find($id);
        if (!$assignment) {
            return response()->json([
                'status' => false,
                'message' => 'Assigned stock not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Assigned stock fetched successfully.',
            'data' => $this->transformAssignments([$assignment])[0],
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

        $assignment = AssignStock::find($id);
        if (!$assignment) {
            return response()->json([
                'status' => false,
                'message' => 'Assigned stock not found.',
            ], 404);
        }

        $validated = $request->validate([
            'employee_id' => ['sometimes', 'required', 'integer', 'exists:employees,id'],
            'stock_management_id' => ['sometimes', 'required', 'integer', 'exists:stock_management,id'],
            'assign_quantity' => ['sometimes', 'required', 'integer', 'min:1'],
            'assign_date' => ['sometimes', 'required', 'date'],
            'remarks' => ['nullable', 'string'],
        ]);

        try {
            $updated = DB::transaction(function () use ($assignment, $validated) {
                $newStockId = (int) ($validated['stock_management_id'] ?? $assignment->stock_management_id);
                $newQuantity = (int) ($validated['assign_quantity'] ?? $assignment->assign_quantity);

                if ($newStockId === (int) $assignment->stock_management_id) {
                    $stock = StockManagement::where('id', $newStockId)->lockForUpdate()->first();
                    if (!$stock) {
                        return null;
                    }

                    $delta = $newQuantity - (int) $assignment->assign_quantity;
                    if ($delta > 0 && (int) $stock->quantity < $delta) {
                        throw new \RuntimeException('Insufficient stock quantity.');
                    }

                    $stock->quantity = (int) $stock->quantity - $delta;
                    $stock->total_price = round(((float) $stock->quantity) * ((float) $stock->price), 2);
                    $stock->save();
                } else {
                    $oldStock = StockManagement::where('id', (int) $assignment->stock_management_id)->lockForUpdate()->first();
                    $newStock = StockManagement::where('id', $newStockId)->lockForUpdate()->first();

                    if (!$oldStock || !$newStock) {
                        return null;
                    }

                    $oldStock->quantity = (int) $oldStock->quantity + (int) $assignment->assign_quantity;
                    $oldStock->total_price = round(((float) $oldStock->quantity) * ((float) $oldStock->price), 2);
                    $oldStock->save();

                    if ((int) $newStock->quantity < $newQuantity) {
                        throw new \RuntimeException('Insufficient stock quantity.');
                    }

                    $newStock->quantity = (int) $newStock->quantity - $newQuantity;
                    $newStock->total_price = round(((float) $newStock->quantity) * ((float) $newStock->price), 2);
                    $newStock->save();
                }

                if (array_key_exists('employee_id', $validated)) {
                    $assignment->employee_id = $validated['employee_id'];
                }
                if (array_key_exists('stock_management_id', $validated)) {
                    $assignment->stock_management_id = $validated['stock_management_id'];
                }
                if (array_key_exists('assign_quantity', $validated)) {
                    $assignment->assign_quantity = $validated['assign_quantity'];
                }
                if (array_key_exists('assign_date', $validated)) {
                    $assignment->assign_date = $validated['assign_date'];
                }
                if (array_key_exists('remarks', $validated)) {
                    $assignment->remarks = $validated['remarks'];
                }

                $assignment->save();

                return $assignment;
            });
        } catch (\RuntimeException $exception) {
            return response()->json([
                'status' => false,
                'message' => $exception->getMessage(),
            ], 422);
        }

        if (!$updated) {
            return response()->json([
                'status' => false,
                'message' => 'Related stock item not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Assigned stock updated successfully.',
            'data' => $this->transformAssignments([$updated])[0],
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

        $assignment = AssignStock::find($id);
        if (!$assignment) {
            return response()->json([
                'status' => false,
                'message' => 'Assigned stock not found.',
            ], 404);
        }

        DB::transaction(function () use ($assignment) {
            $stock = StockManagement::where('id', (int) $assignment->stock_management_id)->lockForUpdate()->first();

            if ($stock) {
                $stock->quantity = (int) $stock->quantity + (int) $assignment->assign_quantity;
                $stock->total_price = round(((float) $stock->quantity) * ((float) $stock->price), 2);
                $stock->save();
            }

            $assignment->delete();
        });

        return response()->json([
            'status' => true,
            'message' => 'Assigned stock deleted successfully.',
        ]);
    }

    private function transformAssignments(array $assignments): array
    {
        $employeeIds = collect($assignments)->pluck('employee_id')->filter()->unique()->values();
        $stockIds = collect($assignments)->pluck('stock_management_id')->filter()->unique()->values();

        $employees = Employee::whereIn('id', $employeeIds)->get()->keyBy('id');
        $stocks = StockManagement::whereIn('id', $stockIds)->get()->keyBy('id');

        return array_map(function (AssignStock $assignment) use ($employees, $stocks) {
            $employee = $employees->get($assignment->employee_id);
            $stock = $stocks->get($assignment->stock_management_id);

            return [
                'id' => $assignment->id,
                'employee_id' => $assignment->employee_id,
                'stock_management_id' => $assignment->stock_management_id,
                'assign_quantity' => $assignment->assign_quantity,
                'assign_date' => $assignment->assign_date,
                'remarks' => $assignment->remarks,
                'created_at' => $assignment->created_at,
                'updated_at' => $assignment->updated_at,
                'employee' => $employee ? [
                    'id' => $employee->id,
                    'emp_name' => $employee->emp_name,
                    'emp_email' => $employee->emp_email,
                ] : null,
                'stock' => $stock ? [
                    'id' => $stock->id,
                    'item_name' => $stock->item_name,
                    'quantity' => $stock->quantity,
                    'price' => $stock->price,
                    'unit' => $stock->unit,
                ] : null,
            ];
        }, $assignments);
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
