<?php

namespace App\Http\Controllers\Interview;

use App\Http\Controllers\Controller;
use App\Models\CandidateAddress;
use App\Models\CandidateDocument;
use App\Models\CandidateEducation;
use App\Models\CandidateExperience;
use App\Models\CandidateFamily;
use App\Models\CandidateInfo;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Validation\Rule;

class CandidateInterviewController extends Controller
{
    public function index(Request $request)
    {
        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:255'],
            'per_page' => ['nullable', 'integer', 'min:1', 'max:100'],
        ]);

        $query = CandidateInfo::query()->with([
            'conductedBy',
            'educations',
            'experiences',
            'address',
            'family',
            'document',
        ]);

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('full_name', 'like', '%' . $search . '%')
                    ->orWhere('email', 'like', '%' . $search . '%')
                    ->orWhere('phone', 'like', '%' . $search . '%')
                    ->orWhere('dob', 'like', '%' . $search . '%')
                    ->orWhere('blood_group', 'like', '%' . $search . '%')
                    ->orWhere('marital_status', 'like', '%' . $search . '%')
                    ->orWhere('nationality', 'like', '%' . $search . '%')
                    ->orWhere('religion', 'like', '%' . $search . '%')
                    ->orWhere('birth_place', 'like', '%' . $search . '%')
                    ->orWhere('place', 'like', '%' . $search . '%')
                    ->orWhere('status', 'like', '%' . $search . '%')
                    ->orWhere('remarks', 'like', '%' . $search . '%')
                    ->orWhereHas('conductedBy', function ($employeeQuery) use ($search) {
                        $employeeQuery->where('emp_name', 'like', '%' . $search . '%')
                            ->orWhere('emp_email', 'like', '%' . $search . '%')
                            ->orWhere('emp_phone', 'like', '%' . $search . '%');
                    });
            });
        }

        $perPage = (int) ($validated['per_page'] ?? 10);
        $candidates = $query->latest()->paginate($perPage);

        return response()->json([
            'status' => true,
            'message' => 'Candidates fetched successfully.',
            'data' => collect($candidates->items())
                ->map(fn (CandidateInfo $candidate) => $this->transformCandidate($candidate))
                ->values()
                ->all(),
            'pagination' => [
                'current_page' => $candidates->currentPage(),
                'last_page' => $candidates->lastPage(),
                'per_page' => $candidates->perPage(),
                'total' => $candidates->total(),
            ],
        ]);
    }

    public function store(Request $request)
    {
        $validated = $this->validatePayload($request);

        $candidate = DB::transaction(function () use ($request, $validated) {
            $candidate = new CandidateInfo();
            $this->fillCandidateInfo($candidate, $request, $validated);
            $candidate->save();

            $this->syncEducation($candidate->id, $validated['educations'] ?? []);
            $this->syncExperiences($candidate->id, $validated['experiences'] ?? []);
            $this->syncAddress($candidate->id, $validated['address'] ?? null);
            $this->syncFamily($candidate->id, $validated['family'] ?? null);
            $this->syncDocument($candidate->id, $validated['document'] ?? null);

            return $candidate->fresh([
                'conductedBy',
                'educations',
                'experiences',
                'address',
                'family',
                'document',
            ]);
        });

        return response()->json([
            'status' => true,
            'message' => 'Candidate created successfully.',
            'data' => $this->transformCandidate($candidate),
        ], 201);
    }

    public function show(int $id)
    {
        $candidate = CandidateInfo::with([
            'conductedBy',
            'educations',
            'experiences',
            'address',
            'family',
            'document',
        ])->find($id);

        if (!$candidate) {
            return response()->json([
                'status' => false,
                'message' => 'Candidate not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Candidate fetched successfully.',
            'data' => $this->transformCandidate($candidate),
        ]);
    }

    public function update(Request $request, int $id)
    {
        $candidate = CandidateInfo::with([
            'conductedBy',
            'educations',
            'experiences',
            'address',
            'family',
            'document',
        ])->find($id);

        if (!$candidate) {
            return response()->json([
                'status' => false,
                'message' => 'Candidate not found.',
            ], 404);
        }

        $validated = $this->validatePayload($request, true, $candidate->id);

        $candidate = DB::transaction(function () use ($request, $candidate, $validated) {
            $this->fillCandidateInfo($candidate, $request, $validated, true);
            $candidate->save();

            if (array_key_exists('educations', $validated)) {
                CandidateEducation::where('candidate_info_id', $candidate->id)->delete();
                $this->syncEducation($candidate->id, $validated['educations']);
            }

            if (array_key_exists('experiences', $validated)) {
                CandidateExperience::where('candidate_info_id', $candidate->id)->delete();
                $this->syncExperiences($candidate->id, $validated['experiences']);
            }

            if (array_key_exists('address', $validated)) {
                CandidateAddress::where('candidate_info_id', $candidate->id)->delete();
                $this->syncAddress($candidate->id, $validated['address']);
            }

            if (array_key_exists('family', $validated)) {
                CandidateFamily::where('candidate_info_id', $candidate->id)->delete();
                $this->syncFamily($candidate->id, $validated['family']);
            }

            if (array_key_exists('document', $validated)) {
                CandidateDocument::where('candidate_info_id', $candidate->id)->delete();
                $this->syncDocument($candidate->id, $validated['document']);
            }

            return $candidate->fresh([
                'conductedBy',
                'educations',
                'experiences',
                'address',
                'family',
                'document',
            ]);
        });

        return response()->json([
            'status' => true,
            'message' => 'Candidate updated successfully.',
            'data' => $this->transformCandidate($candidate),
        ]);
    }

    public function destroy(int $id)
    {
        $candidate = CandidateInfo::with(['document'])->find($id);

        if (!$candidate) {
            return response()->json([
                'status' => false,
                'message' => 'Candidate not found.',
            ], 404);
        }

        if (!empty($candidate->signature) && Storage::disk('public')->exists($candidate->signature)) {
            Storage::disk('public')->delete($candidate->signature);
        }

        $candidate->delete();

        return response()->json([
            'status' => true,
            'message' => 'Candidate deleted successfully.',
        ]);
    }

    private function validatePayload(Request $request, bool $isUpdate = false, ?int $candidateId = null): array
    {
        $requiredRules = $isUpdate ? ['sometimes', 'required'] : ['required'];

        return $request->validate([
            'full_name' => array_merge($requiredRules, ['string', 'max:255']),
            'email' => [
                ...$requiredRules,
                'email',
                'max:255',
                Rule::unique('candidate_infos', 'email')->ignore($candidateId),
            ],
            'phone' => [
                'nullable',
                'string',
                'max:20',
                Rule::unique('candidate_infos', 'phone')->ignore($candidateId),
            ],
            'dob' => ['nullable', 'date'],
            'blood_group' => ['nullable', 'string', 'max:50'],
            'age' => ['nullable', 'string', 'max:20'],
            'height' => ['nullable', 'string', 'max:20'],
            'weight' => ['nullable', 'string', 'max:20'],
            'disability' => ['nullable', 'string', 'max:255'],
            'marital_status' => ['nullable', 'string', 'max:100'],
            'nationality' => ['nullable', 'string', 'max:100'],
            'religion' => ['nullable', 'string', 'max:100'],
            'hobbies' => ['nullable', 'string', 'max:255'],
            'birth_place' => ['nullable', 'string', 'max:255'],
            'date' => ['nullable', 'date'],
            'place' => ['nullable', 'string', 'max:255'],
            'conducted_by' => ['nullable', 'integer', 'exists:employees,id'],
            'status' => ['nullable', 'in:pending,hold,rejected,selected'],
            'remarks' => ['nullable', 'string'],
            'signature' => ['nullable', 'image', 'mimes:jpg,jpeg,png,webp', 'max:2048'],
            'educations' => ['nullable', 'array'],
            'educations.*.qualification' => ['nullable', 'string', 'max:255'],
            'educations.*.institution' => ['nullable', 'string', 'max:255'],
            'educations.*.year_of_passing' => ['nullable', 'integer', 'min:1900', 'max:' . date('Y')],
            'educations.*.grade' => ['nullable', 'string', 'max:100'],
            'educations.*.specialization' => ['nullable', 'string', 'max:255'],
            'address' => ['nullable', 'array'],
            'address.address_line1' => ['nullable', 'string', 'max:255'],
            'address.contact_no' => ['nullable', 'string', 'max:20'],
            'experiences' => ['nullable', 'array'],
            'experiences.*.company_name' => ['nullable', 'string', 'max:255'],
            'experiences.*.post_held' => ['nullable', 'string', 'max:255'],
            'experiences.*.department' => ['nullable', 'string', 'max:255'],
            'experiences.*.tenure' => ['nullable', 'string', 'max:255'],
            'experiences.*.city' => ['nullable', 'string', 'max:255'],
            'experiences.*.current_salary' => ['nullable', 'numeric', 'min:0'],
            'experiences.*.expected_salary' => ['nullable', 'numeric', 'min:0'],
            'family' => ['nullable', 'array'],
            'family.father_name' => array_filter([
                'nullable',
                'string',
                'max:255',
                $candidateId
                    ? Rule::unique('candidate_families', 'father_name')
                        ->where(fn ($query) => $query->where('candidate_info_id', '!=', $candidateId))
                    : Rule::unique('candidate_families', 'father_name'),
            ]),
            'family.mother_name' => ['nullable', 'string', 'max:255'],
            'family.occupation' => ['nullable', 'string', 'max:255'],
            'family.mother_occupation' => ['nullable', 'string', 'max:255'],
            'family.age' => ['nullable', 'string', 'max:20'],
            'document' => ['nullable', 'array'],
            'document.pay_slip' => ['nullable', 'boolean'],
            'document.reliving_letter' => ['nullable', 'boolean'],
            'document.experience_letter' => ['nullable', 'boolean'],
            'document.passport_photo' => ['nullable', 'boolean'],
            'document.id_proof' => ['nullable', 'boolean'],
            'document.address_proof' => ['nullable', 'boolean'],
            'document.graduation_certificate' => ['nullable', 'boolean'],
            'document.10_certificate' => ['nullable', 'boolean'],
            'document.12_certificate' => ['nullable', 'boolean'],
        ]);
    }

    private function fillCandidateInfo(CandidateInfo $candidate, Request $request, array $validated, bool $isUpdate = false): void
    {
        $fields = [
            'full_name',
            'email',
            'phone',
            'dob',
            'blood_group',
            'age',
            'height',
            'weight',
            'disability',
            'marital_status',
            'nationality',
            'religion',
            'hobbies',
            'birth_place',
            'date',
            'place',
            'conducted_by',
            'status',
            'remarks',
        ];

        foreach ($fields as $field) {
            if (!$isUpdate || array_key_exists($field, $validated)) {
                $candidate->{$field} = $validated[$field] ?? null;
            }
        }

        if ($request->hasFile('signature')) {
            if (!empty($candidate->signature) && Storage::disk('public')->exists($candidate->signature)) {
                Storage::disk('public')->delete($candidate->signature);
            }

            $candidate->signature = $request->file('signature')->store('candidate/signatures', 'public');
        }
    }

    private function syncEducation(int $candidateInfoId, array $educations): void
    {
        foreach ($educations as $education) {
            $record = new CandidateEducation();
            $record->candidate_info_id = $candidateInfoId;
            $record->qualification = $education['qualification'] ?? null;
            $record->institution = $education['institution'] ?? null;
            $record->year_of_passing = $education['year_of_passing'] ?? null;
            $record->grade = $education['grade'] ?? null;
            $record->specialization = $education['specialization'] ?? null;
            $record->save();
        }
    }

    private function syncAddress(int $candidateInfoId, ?array $address): void
    {
        if (!$address) {
            return;
        }

        $record = new CandidateAddress();
        $record->candidate_info_id = $candidateInfoId;
        $record->address_line1 = $address['address_line1'] ?? null;
        $record->contact_no = $address['contact_no'] ?? null;
        $record->save();
    }

    private function syncExperiences(int $candidateInfoId, array $experiences): void
    {
        foreach ($experiences as $experience) {
            $record = new CandidateExperience();
            $record->candidate_info_id = $candidateInfoId;
            $record->company_name = $experience['company_name'] ?? null;
            $record->post_held = $experience['post_held'] ?? null;
            $record->department = $experience['department'] ?? null;
            $record->tenure = $experience['tenure'] ?? null;
            $record->city = $experience['city'] ?? null;
            $record->current_salary = $experience['current_salary'] ?? null;
            $record->expected_salary = $experience['expected_salary'] ?? null;
            $record->save();
        }
    }

    private function syncFamily(int $candidateInfoId, ?array $family): void
    {
        if (!$family) {
            return;
        }

        $record = new CandidateFamily();
        $record->candidate_info_id = $candidateInfoId;
        $record->father_name = $family['father_name'] ?? null;
        $record->mother_name = $family['mother_name'] ?? null;
        $record->occupation = $family['occupation'] ?? null;
        $record->mother_occupation = $family['mother_occupation'] ?? null;
        $record->age = $family['age'] ?? null;
        $record->save();
    }

    private function syncDocument(int $candidateInfoId, ?array $document): void
    {
        if (!$document) {
            return;
        }

        $record = new CandidateDocument();
        $record->candidate_info_id = $candidateInfoId;
        $record->pay_slip = $document['pay_slip'] ?? null;
        $record->reliving_letter = $document['reliving_letter'] ?? null;
        $record->experience_letter = $document['experience_letter'] ?? null;
        $record->passport_photo = $document['passport_photo'] ?? null;
        $record->id_proof = $document['id_proof'] ?? null;
        $record->address_proof = $document['address_proof'] ?? null;
        $record->graduation_certificate = $document['graduation_certificate'] ?? null;
        $record->{'10_certificate'} = $document['10_certificate'] ?? null;
        $record->{'12_certificate'} = $document['12_certificate'] ?? null;
        $record->save();
    }

    private function transformCandidate(CandidateInfo $candidate): array
    {
        $data = $candidate->toArray();
        $data['conducted_by'] = $candidate->getRawOriginal('conducted_by');
        $data['signature'] = $candidate->signature ? url(Storage::url($candidate->signature)) : null;
        $data['conducted_by_employee'] = $candidate->conductedBy ? $candidate->conductedBy->toArray() : null;
        $data['educations'] = collect($candidate->educations ?? [])->map(function (CandidateEducation $education) {
            return $education->toArray();
        })->values()->all();
        $data['experiences'] = collect($candidate->experiences ?? [])->map(function (CandidateExperience $experience) {
            return $experience->toArray();
        })->values()->all();
        $data['address'] = $candidate->address ? $candidate->address->toArray() : null;
        $data['family'] = $candidate->family ? $candidate->family->toArray() : null;
        $data['document'] = $candidate->document ? $candidate->document->toArray() : null;

        return $data;
    }
}
