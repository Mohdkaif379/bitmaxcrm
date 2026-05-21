<?php

namespace App\Http\Controllers\Projects;

use App\Http\Controllers\Controller;
use App\Models\Project;
use App\Models\Admin;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;

class ProjectController extends Controller
{
    public function index(Request $request)
    {
        if ($authResponse = $this->ensureAdminAuthorized($request)) {
            return $authResponse;
        }

        $projects = Project::with('tl')->latest()->get();

        return response()->json([
            'status' => true,
            'message' => 'Projects fetched successfully.',
            'data' => $projects,
        ]);
    }

    public function store(Request $request)
    {
        if ($authResponse = $this->ensureAdminAuthorized($request)) {
            return $authResponse;
        }

        $validated = $request->validate([
            'title' => 'required|string|max:255',
            'deadline' => 'required|date',
            'tl_id' => 'required|exists:employees,id',
            'status' => ['sometimes', 'string', Rule::in(['pending', 'inprogress', 'completed', 'testing', 'review', 'done'])],
        ]);

        $project = DB::transaction(function () use ($validated) {
            $project = new Project();
            $project->project_code = $this->generateProjectCode();
            $project->title = $validated['title'];
            $project->deadline = $validated['deadline'];
            $project->status = $validated['status'] ?? 'pending';
            $project->tl_id = $validated['tl_id'];
            $project->save();

            return $project;
        });

        return response()->json([
            'status' => true,
            'message' => 'Project created successfully.',
            'data' => $project,
        ], 201);
    }

    public function show(Request $request, $id)
    {
        if ($authResponse = $this->ensureAdminAuthorized($request)) {
            return $authResponse;
        }

        $project = Project::with('tl')->find($id);

        if (!$project) {
            return response()->json(['status' => false, 'message' => 'Project not found.'], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Project fetched successfully.',
            'data' => $project,
        ]);
    }

    public function update(Request $request, $id)
    {
        if ($authResponse = $this->ensureAdminAuthorized($request)) {
            return $authResponse;
        }

        $project = Project::find($id);
        if (!$project) {
            return response()->json(['status' => false, 'message' => 'Project not found.'], 404);
        }

        $validated = $request->validate([
            'title' => 'sometimes|string|max:255',
            'deadline' => 'sometimes|date',
            'status' => ['sometimes', 'string', Rule::in(['pending', 'inprogress', 'completed', 'testing', 'review', 'done'])],
            'tl_id' => 'sometimes|exists:employees,id',
        ]);

        $project->update($validated);

        return response()->json([
            'status' => true,
            'message' => 'Project updated successfully.',
            'data' => $project->load('tl'),
        ]);
    }

    public function destroy(Request $request, $id)
    {
        if ($authResponse = $this->ensureAdminAuthorized($request)) {
            return $authResponse;
        }

        $project = Project::find($id);
        if (!$project) {
            return response()->json(['status' => false, 'message' => 'Project not found.'], 404);
        }

        $project->delete();

        return response()->json([
            'status' => true,
            'message' => 'Project deleted successfully.',
        ]);
    }

    private function generateProjectCode(): string
    {
        $year = date('y');

        $lastProject = Project::where('project_code', 'like', 'BT/PROJ%/' . $year)
            ->orderBy('id', 'desc')
            ->first();

        $sequence = 1;
        if ($lastProject) {
            if (preg_match('/BT\/PROJ(\d+)\//', $lastProject->project_code, $matches)) {
                $sequence = (int) $matches[1] + 1;
            }
        }

        return sprintf('BT/PROJ%03d/%s', $sequence, $year);
    }

    private function ensureAdminAuthorized(Request $request): ?\Illuminate\Http\JsonResponse
    {
        $token = $request->bearerToken();
        if (!$token) {
            return response()->json(['status' => false, 'message' => 'Unauthorized.'], 401);
        }

        $payload = $this->decodeJwtToken($token);
        if (!$payload || !in_array($payload['role'] ?? null, ['admin', 'subadmin', 'sub_admin'])) {
            return response()->json(['status' => false, 'message' => 'Unauthorized.'], 401);
        }

        $admin = Admin::find((int) ($payload['sub'] ?? 0));
        if (!$admin) {
            return response()->json(['status' => false, 'message' => 'Unauthorized.'], 401);
        }

        $request->attributes->set('auth_admin', $admin);
        return null;
    }

    private function decodeJwtToken(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) return null;

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;
        $payloadJson = base64_decode(strtr($encodedPayload, '-_', '+/'), true);
        if ($payloadJson === false) return null;

        return json_decode($payloadJson, true);
    }
}
