<?php

namespace App\Http\Controllers\Email;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;
use Throwable;

class EmailController extends Controller
{
    public function sendContactForm(Request $request)
    {
        $validated = $request->validate([
            'full_name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:255'],
            'phone' => ['nullable', 'string', 'max:30'],
            'service' => ['required', 'string', 'max:255'],
            'message' => ['required', 'string'],
            'terms' => ['required', 'boolean'],
        ]);

        $toAddress = (string) config('mail.from.address');
        $fromAddress = (string) config('mail.from.address');
        $fromName = (string) config('mail.from.name', 'Website Contact Form');

        try {
            Mail::send([], [], function ($mail) use ($validated, $toAddress, $fromAddress, $fromName) {
                $mail->to($toAddress)
                    ->from($fromAddress, $fromName)
                    ->replyTo($validated['email'], $validated['full_name'])
                    ->subject('New Contact Form Submission')
                    ->html(
                        '<div style="font-family:Arial,sans-serif;max-width:680px;margin:0 auto;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden;">'
                        . '<div style="background:#0f172a;color:#ffffff;padding:14px 18px;">'
                        . '<h2 style="margin:0;font-size:18px;">New Contact Inquiry</h2>'
                        . '<p style="margin:6px 0 0;font-size:12px;opacity:.9;">Submitted from website contact form</p>'
                        . '</div>'
                        . '<div style="padding:16px 18px;background:#ffffff;">'
                        . '<table style="width:100%;border-collapse:collapse;">'
                        . '<tr><td style="padding:8px 0;font-size:13px;color:#6b7280;width:160px;">Full Name</td><td style="padding:8px 0;font-size:14px;color:#111827;"><strong>' . e($validated['full_name']) . '</strong></td></tr>'
                        . '<tr><td style="padding:8px 0;font-size:13px;color:#6b7280;">Email</td><td style="padding:8px 0;font-size:14px;color:#111827;">' . e($validated['email']) . '</td></tr>'
                        . '<tr><td style="padding:8px 0;font-size:13px;color:#6b7280;">Phone</td><td style="padding:8px 0;font-size:14px;color:#111827;">' . e((string) ($validated['phone'] ?? 'N/A')) . '</td></tr>'
                        . '<tr><td style="padding:8px 0;font-size:13px;color:#6b7280;">Service</td><td style="padding:8px 0;font-size:14px;color:#111827;">' . e($validated['service']) . '</td></tr>'
                        . '<tr><td style="padding:8px 0;font-size:13px;color:#6b7280;">Terms Accepted</td><td style="padding:8px 0;font-size:14px;color:#111827;">' . (($validated['terms'] ?? false) ? 'Yes' : 'No') . '</td></tr>'
                        . '</table>'
                        . '<div style="margin-top:14px;padding:12px;border:1px solid #e5e7eb;border-radius:8px;background:#f8fafc;">'
                        . '<div style="font-size:13px;color:#6b7280;margin-bottom:6px;">Message</div>'
                        . '<div style="font-size:14px;color:#111827;line-height:1.6;">' . nl2br(e($validated['message'])) . '</div>'
                        . '</div>'
                        . '</div>'
                        . '</div>'
                    );
            });
        } catch (Throwable $exception) {
            return response()->json([
                'status' => false,
                'message' => 'Failed to send contact form email.',
                'error' => $exception->getMessage(),
            ], 500);
        }

        return response()->json([
            'status' => true,
            'message' => 'Contact form submitted successfully.',
        ]);
    }
}
