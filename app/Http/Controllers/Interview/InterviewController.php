<?php

namespace App\Http\Controllers\Interview;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Interview;
use App\Models\InterviewRound;
use App\Models\Log;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;

class InterviewController extends Controller
{
    public function index(Request $request)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:255'],
            'status' => ['nullable', 'string', 'max:100'],
            'job_profile' => ['nullable', 'string', 'max:255'],
            'interview_date' => ['nullable', 'date'],
        ]);

        $query = Interview::with('rounds');

        if (!empty($validated['status'])) {
            $query->where('status', $validated['status']);
        }

        if (!empty($validated['job_profile'])) {
            $query->where('job_profile', $validated['job_profile']);
        }

        if (!empty($validated['interview_date'])) {
            $query->whereDate('interview_date', $validated['interview_date']);
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('job_profile', 'like', '%' . $search . '%')
                    ->orWhere('candidate_name', 'like', '%' . $search . '%')
                    ->orWhere('candidate_email', 'like', '%' . $search . '%')
                    ->orWhere('candidate_phone', 'like', '%' . $search . '%')
                    ->orWhere('location', 'like', '%' . $search . '%')
                    ->orWhere('status', 'like', '%' . $search . '%')
                    ->orWhere('experience', 'like', '%' . $search . '%')
                    ->orWhere('final_feedback', 'like', '%' . $search . '%');
            });
        }

        $interviews = $query->latest()->paginate(10);

        return response()->json([
            'status' => true,
            'message' => 'Interviews fetched successfully.',
            'data' => collect($interviews->items())->map(fn (Interview $interview) => $this->transformInterview($interview))->values()->all(),
            'pagination' => [
                'current_page' => $interviews->currentPage(),
                'last_page' => $interviews->lastPage(),
                'per_page' => $interviews->perPage(),
                'total' => $interviews->total(),
            ],
        ]);
    }

    public function store(Request $request)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $validated = $this->validatePayload($request);

        $interview = DB::transaction(function () use ($request, $validated) {
            $interview = new Interview();
            $this->fillInterview($interview, $request, $validated);
            $interview->save();

            foreach ($validated['round_details'] as $round) {
                $this->createRound($interview->id, $round);
            }

            return $interview->fresh('rounds');
        });

        $this->logInterviewAction($request, $admin, $interview, 'create', 'created interview for');

        return response()->json([
            'status' => true,
            'message' => 'Interview created successfully.',
            'data' => $this->transformInterview($interview),
        ], 201);
    }

    public function show(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $interview = Interview::with('rounds')->find($id);
        if (!$interview) {
            return response()->json([
                'status' => false,
                'message' => 'Interview not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Interview fetched successfully.',
            'data' => $this->transformInterview($interview),
        ]);
    }

    public function update(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $interview = Interview::with('rounds')->find($id);
        if (!$interview) {
            return response()->json([
                'status' => false,
                'message' => 'Interview not found.',
            ], 404);
        }

        $validated = $this->validatePayload($request, true);

        $updatedInterview = DB::transaction(function () use ($request, $interview, $validated) {
            $this->fillInterview($interview, $request, $validated, true);
            $interview->save();

            if (array_key_exists('round_details', $validated)) {
                InterviewRound::where('interview_id', $interview->id)->delete();
                foreach ($validated['round_details'] as $round) {
                    $this->createRound($interview->id, $round);
                }
            }

            return $interview->fresh('rounds');
        });

        $this->logInterviewAction($request, $admin, $updatedInterview, 'update', 'updated interview for');

        return response()->json([
            'status' => true,
            'message' => 'Interview updated successfully.',
            'data' => $this->transformInterview($updatedInterview),
        ]);
    }

    public function destroy(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $interview = Interview::find($id);
        if (!$interview) {
            return response()->json([
                'status' => false,
                'message' => 'Interview not found.',
            ], 404);
        }

        $candidateName = $interview->candidate_name ?: 'unknown candidate';
        if (!empty($interview->candidate_resume) && Storage::disk('public')->exists($interview->candidate_resume)) {
            Storage::disk('public')->delete($interview->candidate_resume);
        }

        $interview->delete();
        $this->logInterviewDeleteAction($request, $admin, $candidateName);

        return response()->json([
            'status' => true,
            'message' => 'Interview deleted successfully.',
        ]);
    }

    private function validatePayload(Request $request, bool $isUpdate = false): array
    {
        $requiredRules = $isUpdate ? ['sometimes', 'required'] : ['required'];

        return $request->validate([
            'job_profile' => array_merge($requiredRules, ['string', 'max:255']),
            'scheduled_at' => array_merge($requiredRules, ['date']),
            'location' => array_merge($requiredRules, ['string', 'max:255']),
            'candidate_name' => array_merge($requiredRules, ['string', 'max:255']),
            'candidate_email' => array_merge($requiredRules, ['email', 'max:255']),
            'candidate_phone' => array_merge($requiredRules, ['string', 'max:20']),
            'experience' => array_merge($requiredRules, ['string', 'max:255']),
            'interview_date' => array_merge($requiredRules, ['date']),
            'interview_time' => array_merge($requiredRules, ['date_format:H:i']),
            'status' => ['nullable', 'string', 'max:100'],
            'candidate_resume' => ['nullable', 'file', 'mimes:pdf,doc,docx', 'max:10240'],
            'final_feedback' => ['nullable', 'string'],
            'round_details' => $isUpdate ? ['sometimes', 'array', 'min:1'] : ['required', 'array', 'min:1'],
            'round_details.*.round_name' => ['required_with:round_details', 'string', 'max:255'],
            'round_details.*.remarks' => ['required_with:round_details', 'string'],
            'round_details.*.interviewer_name' => ['required_with:round_details', 'string', 'max:255'],
        ]);
    }

    private function fillInterview(Interview $interview, Request $request, array $validated, bool $isUpdate = false): void
    {
        $fields = [
            'job_profile',
            'scheduled_at',
            'location',
            'candidate_name',
            'candidate_email',
            'candidate_phone',
            'experience',
            'interview_date',
            'interview_time',
            'status',
            'final_feedback',
        ];

        foreach ($fields as $field) {
            if (!$isUpdate || array_key_exists($field, $validated)) {
                if ($field === 'status') {
                    $interview->{$field} = $validated[$field] ?? 'scheduled';
                } else {
                    $interview->{$field} = $validated[$field] ?? null;
                }
            }
        }

        if ($request->hasFile('candidate_resume')) {
            if (!empty($interview->candidate_resume) && Storage::disk('public')->exists($interview->candidate_resume)) {
                Storage::disk('public')->delete($interview->candidate_resume);
            }
            $interview->candidate_resume = $request->file('candidate_resume')->store('interviews/resumes', 'public');
        }
    }

    private function createRound(int $interviewId, array $round): void
    {
        $roundItem = new InterviewRound();
        $roundItem->interview_id = $interviewId;
        $roundItem->round_name = $round['round_name'];
        $roundItem->remarks = $round['remarks'];
        $roundItem->interviewer_name = $round['interviewer_name'];
        $roundItem->save();
    }

    private function transformInterview(Interview $interview): array
    {
        $data = $interview->toArray();
        $data['candidate_resume'] = $interview->candidate_resume ? url(Storage::url($interview->candidate_resume)) : null;
        $data['round_details'] = collect($interview->rounds ?? [])->map(function (InterviewRound $round) {
            return [
                'id' => $round->id,
                'round_name' => $round->round_name,
                'remarks' => $round->remarks,
                'interviewer_name' => $round->interviewer_name,
                'created_at' => $round->created_at,
                'updated_at' => $round->updated_at,
            ];
        })->values()->all();
        unset($data['rounds']);

        return $data;
    }

    private function authenticatedAdminOrSubAdminFromToken(Request $request): ?Admin
    {
        $token = $request->bearerToken();
        if (!$token) {
            return null;
        }

        $payload = $this->decodeJwtToken($token);
        if (!$payload) {
            return null;
        }

        $role = strtolower((string) ($payload['role'] ?? ''));
        if (!in_array($role, ['admin', 'sub_admin', 'subadmin'], true)) {
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

    private function logInterviewAction(
        Request $request,
        Admin $admin,
        Interview $interview,
        string $action,
        string $actionText
    ): void {
        $adminName = $admin->full_name ?: 'unknown admin';
        $candidateName = $interview->candidate_name ?: 'unknown candidate';

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = null;
        $log->model = class_basename($interview);
        $log->action = $action;
        $log->description = sprintf(
            'admin(%s) %s candidate(%s)',
            $adminName,
            $actionText,
            $candidateName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function logInterviewDeleteAction(Request $request, Admin $admin, string $candidateName): void
    {
        $adminName = $admin->full_name ?: 'unknown admin';

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = null;
        $log->model = class_basename(Interview::class);
        $log->action = 'delete';
        $log->description = sprintf(
            'admin(%s) deleted interview for candidate(%s)',
            $adminName,
            $candidateName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }
}
