<?php

namespace App\Http\Controllers\MYProject;

use App\Http\Controllers\Controller;
use App\Models\Project;
use App\Models\Employee;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class MyProjectController extends Controller
{
    public function index(Request $request)
    {
        $token = $request->bearerToken();
        if (!$token) {
            return response()->json(['status' => false, 'message' => 'Bearer token is required.'], 401);
        }

        $payload = $this->decodeJwtToken($token);
        if (!$payload) {
            return response()->json(['status' => false, 'message' => 'Invalid or expired token.'], 401);
        }

        // Allow 'employee' and 'tl' roles (as per recent updates)
        if (!in_array($payload['role'] ?? null, ['employee', 'tl', 'TL'])) {
            return response()->json(['status' => false, 'message' => 'Unauthorized role.'], 403);
        }

        $employeeId = (int) ($payload['sub'] ?? 0);
        if ($employeeId <= 0) {
            return response()->json(['status' => false, 'message' => 'Invalid user ID in token.'], 401);
        }

        // Fetch projects where the authenticated employee is the TL
        $projects = Project::where('tl_id', $employeeId)
            ->with('tl') // Optional: include self info if needed
            ->latest()
            ->get();

        return response()->json([
            'status' => true,
            'message' => 'My projects fetched successfully.',
            'data' => $projects,
        ]);
    }

    public function updateStatus(Request $request, $id)
    {
        $token = $request->bearerToken();
        if (!$token) {
            return response()->json(['status' => false, 'message' => 'Bearer token is required.'], 401);
        }

        $payload = $this->decodeJwtToken($token);
        if (!$payload) {
            return response()->json(['status' => false, 'message' => 'Invalid or expired token.'], 401);
        }

        $employeeId = (int) ($payload['sub'] ?? 0);
        
        $project = Project::find($id);

        if (!$project) {
            return response()->json(['status' => false, 'message' => 'Project not found.'], 404);
        }

        // Verify this project is assigned to this TL
        if ($project->tl_id !== $employeeId) {
            return response()->json(['status' => false, 'message' => 'You are not authorized to update this project.'], 403);
        }

        $validated = $request->validate([
            'status' => ['required', 'string', \Illuminate\Validation\Rule::in(['pending', 'inprogress', 'completed', 'testing', 'review', 'done'])],
        ]);

        $project->update(['status' => $validated['status']]);

        return response()->json([
            'status' => true,
            'message' => 'Project status updated successfully.',
            'data' => $project,
        ]);
    }

    private function decodeJwtToken(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) return null;

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;
        $payloadJson = $this->base64UrlDecode($encodedPayload);
        if ($payloadJson === false) return null;

        $payload = json_decode($payloadJson, true);
        if (!is_array($payload)) return null;

        // Blacklist check (consistent with EmployeeLoginController)
        $blacklistKey = 'employee_jwt_blacklist:' . hash('sha256', $token);
        if (Cache::has($blacklistKey)) {
            return null;
        }

        return $payload;
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
