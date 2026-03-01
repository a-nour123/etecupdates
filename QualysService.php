<?php

namespace App\Services;

use App\Jobs\ProcessVulnerabilityBatch;
use App\Jobs\TenableImport;
use App\Jobs\TenableImportInfoVuln;
use App\Models\QualysAuth;
use App\Models\TenableAsyncHistory;
use GuzzleHttp\Client;
use App\Models\TenableAuth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Http;

class QualysService
{
    /** Default Qualys KSA API base URL (used when not set in QualysAuth) */
    public const DEFAULT_QUALYS_BASE_URL = 'https://qualysapi.qg1.apps.qualysksa.com';

    /** Qualys Login FAQ (shown when credentials fail) */
    public const QUALYS_LOGIN_FAQ = 'http://www.qualys.com/support/online/login_trouble/';

    protected $baseUrl;
    protected $username;
    protected $password;
    private $limit = 10;

    public function __construct()
    {
        $setting = QualysAuth::first();
        $this->username = $setting ? $setting->username : null;
        $this->password = $setting ? $setting->password : null;
        $apiUrl = $setting ? trim($setting->api_url ?? '') : '';
        $this->baseUrl = $apiUrl !== '' ? rtrim($apiUrl, '/') : self::DEFAULT_QUALYS_BASE_URL;
    }

    /**
     * Get the Qualys base URL (no trailing slash).
     */
    public function getBaseUrl(): string
    {
        return $this->baseUrl;
    }

    /**
     * Build a full Qualys URL from a path (path should start with /).
     */
    protected function url(string $path): string
    {
        return $this->baseUrl . (isset($path[0]) && $path[0] === '/' ? $path : '/' . $path);
    }

    /**
     * Check credentials using Qualys API only (Basic Auth).
     * Does not use GUI login — use this for "test connection" or before sync.
     *
     * @return array{ok: bool, message: string, faq_link?: string}
     */
    public function checkCredentials(): array
    {
        try {
            $response = Http::withHeaders(['X-Requested-With' => 'Curl Sample'])
                ->withBasicAuth($this->username, $this->password)
                ->get($this->url('/api/2.0/fo/scan/'), [
                    'action' => 'list',
                    'state' => 'Finished',
                    'show_last' => 1,
                ]);

            if ($response->successful()) {
                return ['ok' => true, 'message' => 'Connection successful.'];
            }

            $body = $response->body();
            $invalid = $response->status() === 401
                || str_contains($body, 'Invalid credentials')
                || str_contains($body, 'Invalid Credentials');

            return [
                'ok' => false,
                'message' => $invalid
                    ? 'Invalid credentials. Please refer to the Login FAQ for assistance.'
                    : ($body ?: 'API request failed.'),
                'faq_link' => self::QUALYS_LOGIN_FAQ,
            ];
        } catch (\Exception $e) {
            Log::error('Qualys API check failed', ['error' => $e->getMessage()]);
            return [
                'ok' => false,
                'message' => $e->getMessage(),
                'faq_link' => self::QUALYS_LOGIN_FAQ,
            ];
        }
    }

    // public function authenticate()
    // {

    //     try {
    //         // Step 1: Get Finished Scans
    //         $scanListResponse = Http::withHeaders([
    //             'X-Requested-With' => 'Curl Sample',
    //         ])
    //         ->withBasicAuth($this->username, $this->password)
    //         ->get('https://qualysguard.qg1.apps.qualysksa.com/api/2.0/fo/scan/', [
    //             'action' => 'list',
    //             'state' => 'Finished',
    //             'show_last' => 1,   // ✅ Limit API to return max 10 scans
    //         ]);

    //         $scanRefs = [];
    //         if ($scanListResponse->successful()) {
    //             $xml = simplexml_load_string($scanListResponse->body());
    //             foreach ($xml->RESPONSE->SCAN_LIST->SCAN as $scan) {
    //                 $scanRefs[] = (string) $scan->REF;
    //             }
    //         }
    //         // Step 2: Fetch QIDs from each scan
    //         $qids = [];
    //         foreach ($scanRefs as $scanRef) {

    //             $scanFetchResponse = Http::withHeaders([
    //                 'X-Requested-With' => 'Curl Sample',
    //             ])
    //             ->withBasicAuth($this->username, $this->password)
    //             ->get('https://qualysguard.qg1.apps.qualysksa.com/api/2.0/fo/scan/', [
    //                 'action' => 'fetch',
    //                 'scan_ref' => $scanRef,
    //                 'output_format' => 'json',   // ✅ <-- Use JSON (easy to parse)
    //             ]);


    //             if ($scanFetchResponse->successful()) {
    //                 $jsonData = $scanFetchResponse->json();
    //                 foreach ($jsonData as $qid) {
    //                     $qids[] = (string) $qid['qid'];
    //                 }
    //             }

    //         }


    //         $qids = array_values(array_unique($qids));
    //         // Step 3: Fetch Vulnerability Details from KnowledgeBase
    //         $vulnDetails = [];
    //         $batchSize = 100;
    //         $chunks = array_chunk($qids, $batchSize);

    //         foreach ($chunks as $batch) {
    //             $kbResponse = Http::withHeaders([
    //                 'X-Requested-With' => 'Curl Sample',
    //             ])
    //             ->withBasicAuth($this->username, $this->password)
    //             ->get('https://qualysguard.qg1.apps.qualysksa.com/api/2.0/fo/knowledge_base/vuln/', [
    //                 'action' => 'list',
    //                 'ids' => implode(',', $batch),
    //             ]);

    //             if ($kbResponse->successful()) {
    //                 $xmlKB = simplexml_load_string($kbResponse->body());

    //                 foreach ($xmlKB->RESPONSE->VULN_LIST->VULN as $vuln) {
    //                     $qid = (string) $vuln->QID;
    //                     $vulnDetails[$qid] = [
    //                         'title' => (string) $vuln->TITLE,
    //                         'qid' => $qid,
    //                         'severity' => (string) $vuln->SEVERITY_LEVEL,
    //                         'impact' => (string) $vuln->IMPACT,
    //                         'solution' => (string) $vuln->SOLUTION,
    //                     ];
    //                 }
    //             }
    //         }


    //         // Dispatch job to import vulnerabilities
    //         dispatch(new \App\Jobs\ImportQualysVulnJob($vulnDetails));
    //         return true;

    //     } catch (\Exception $e) {
    //         Log::error('Qualys authentication exception', ['error' => $e->getMessage()]);
    //         return null;
    //     }
    // }

      public function fetchCSV()
    {
        $session = curl_init();
         

        // === Step 1: Login ===
        $loginUrl = $this->url('/fo/user_login.php');
        curl_setopt_array($session, [
            CURLOPT_URL => $loginUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_HEADER => true,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
                'Referer: ' . $this->baseUrl . '/qglogin/index.html',
                'Origin: ' . $this->baseUrl,
                'X-Requested-With: XMLHttpRequest',
                'User-Agent: Mozilla/5.0'
            ],
            CURLOPT_POSTFIELDS => http_build_query([
                'UserLogin' => $this->username,
                'UserPasswd' => $this->password,
                '_form_action1' => 'Please wait...',
                '_form_action' => 'Login',
                '_form_visited' => 1,
                'timezone' => 'Africa/Cairo',
                'gmtoffset' => -180,
                'timezone_abbr' => 'EEST',
                'is_dst' => 1
            ])
        ]);

        $loginResponse = curl_exec($session);
        if ($loginResponse === false) {
            return response('Login failed: ' . curl_error($session), 500);
        }

        preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $loginResponse, $matches);
        $cookies = implode('; ', array_map('trim', $matches[1]));

        if (!str_contains($loginResponse, '"status":"true"')) {
            return response('Login failed: unexpected response', 500);
        }

        curl_reset($session);

        // === Step 2: Stream CSV ===
        $fields = implode(',', [
            'cve','cveDescription','cvssv2Base','cvssv3Base','CVSSRatingLabels','qid','title','severity',
            'kbSeverity','typeDetected','lastDetected','firstDetected','protocol','port','vulnStatus',
            'assetId','assetName','assetIp','tags','solution','results','disabled','ignored','qvsScore',
            'detectionAge','publishedDate','patchReleased','category','rti','operatingSystem','lastFixed',
            'lastReopened','timesFound','threat','isQualysPatchable','assetCriticalScore','assetRiskScore',
            'vulnTags.name'
        ]);

        $csvUrl = $this->url('/portal-front/rest/assetview/1.0/assetvuln/v2/datalist/download/CSV') . '?' . http_build_query([
            'reportType' => 'CSV',
            'showCVECentric' => 'true',
            'fields' => $fields,
            'timezone' => 'Asia/Aden',
            'limit' => 100,
            'offset' => 0,
            'groupByPivot' => 'VM',
            'havingQuery' => 'vulnerabilities.found: TRUE',
            'query' => ''
        ]);

        curl_setopt_array($session, [
            CURLOPT_URL => $csvUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                "Cookie: $cookies",
                'User-Agent: Mozilla/5.0',
                'Referer: ' . $this->baseUrl . '/',
                'X-Requested-With: XMLHttpRequest',
            ]
        ]);

        $csv = curl_exec($session);
        if (!$csv) {
            return response('CSV fetch failed: ' . curl_error($session), 500);
        }

        $rows = preg_split('/\r\n|\n|\r/', $csv);
        $output = '';
        $headerMatched = false;
        $count = 0;

        $expectedHeader = [
            "CVE","CVE-Description","CVSSv2 Base (nvd)","CVSSv3.1 Base (nvd)","QID","Title","Severity","KB Severity",
            "Type Detected","Last Detected","First Detected","Protocol","Port","Status","Asset Id","Asset Name",
            "Asset IPV4","Asset IPV6","Solution","Asset Tags","Disabled","Ignored","QVS Score","Detection AGE",
            "Published Date","Patch Released","Category","CVSS Rating Labels","RTI","Operating System","Last Fixed",
            "Last Reopened","Times Detected","Threat","Vuln Patchable","Asset Critical Score","TruRisk Score",
            "Vulnerability Tags","Results"
        ];

        foreach ($rows as $line) {
            $parsed = str_getcsv($line);
            if (!$headerMatched && $parsed === $expectedHeader) {
                $output .= "<pre>" . implode(" | ", $parsed) . "\n";
                $output .= str_repeat('-', 20 * count($parsed)) . "\n";
                $headerMatched = true;
                continue;
            }

            if ($headerMatched && count($parsed) === count($expectedHeader)) {
                $output .= implode(" | ", $parsed) . "\n";
                if (++$count >= $this->limit) break;
            }
        }

        // === Step 3: Logout ===
        curl_setopt_array($session, [
            CURLOPT_URL => $this->url('/portal-front/rest/passport/logout') . '?',
            CURLOPT_HTTPHEADER => [
                "Cookie: $cookies",
                'User-Agent: Mozilla/5.0',
                'Referer: ' . $this->baseUrl . '/vm/',
                'Accept: /'
            ],
            CURLOPT_RETURNTRANSFER => true
        ]);

        curl_exec($session);
        curl_close($session);
        dd($output);

        return response($output . "</pre>", 200)
            ->header('Content-Type', 'text/html; charset=utf-8');
    }



    // public function authenticate()
    // {
    //     try {
    //         // Step 1: Get Finished Scans
    //         $scanListResponse = Http::withHeaders([
    //             'X-Requested-With' => 'Curl Sample',
    //         ])
    //         ->withBasicAuth($this->username, $this->password)
    //         ->get('https://qualysguard.qg1.apps.qualysksa.com/api/2.0/fo/scan/', [
    //             'action' => 'list',
    //             'state' => 'Finished',
    //             'show_last' => 1,
    //         ]);

    //         $scanRefs = [];
    //         if ($scanListResponse->successful()) {
    //             $xml = simplexml_load_string($scanListResponse->body());
    //             foreach ($xml->RESPONSE->SCAN_LIST->SCAN as $scan) {
    //                 $scanRefs[] = (string) $scan->REF;
    //             }
    //         }

    //         // Step 2: Fetch QIDs from each scan
    //         $qids = [];
    //         foreach ($scanRefs as $scanRef) {
    //             $scanFetchResponse = Http::withHeaders([
    //                 'X-Requested-With' => 'Curl Sample',
    //             ])
    //             ->withBasicAuth($this->username, $this->password)
    //             ->get('https://qualysguard.qg1.apps.qualysksa.com/api/2.0/fo/scan/', [
    //                 'action' => 'fetch',
    //                 'scan_ref' => $scanRef,
    //                 'output_format' => 'json',
    //             ]);

    //             if ($scanFetchResponse->successful()) {
    //                 $jsonData = $scanFetchResponse->json();
    //                 foreach ($jsonData as $qid) {
    //                     $qids[] = (string) $qid['qid'];
    //                 }
    //             }
    //         }

    //         $qids = array_values(array_unique($qids));
            
    //         // Step 3: Fetch Vulnerability Details from KnowledgeBase
    //         $vulnDetails = [];
    //         $batchSize = 100;
    //         $chunks = array_chunk($qids, $batchSize);

    //         foreach ($chunks as $batch) {
    //             $kbResponse = Http::withHeaders([
    //                 'X-Requested-With' => 'Curl Sample',
    //             ])
    //             ->withBasicAuth($this->username, $this->password)
    //             ->get('https://qualysguard.qg1.apps.qualysksa.com/api/2.0/fo/knowledge_base/vuln/', [
    //                 'action' => 'list',
    //                 'ids' => implode(',', $batch),
    //             ]);

    //             if ($kbResponse->successful()) {
    //                 $xmlKB = simplexml_load_string($kbResponse->body());
    //                 foreach ($xmlKB->RESPONSE->VULN_LIST->VULN as $vuln) {
    //                     $qid = (string) $vuln->QID;
    //                     $vulnDetails[$qid] = [
    //                         'title' => (string) $vuln->TITLE,
    //                         'qid' => $qid,
    //                         'severity' => (string) $vuln->SEVERITY_LEVEL,
    //                         'impact' => (string) $vuln->IMPACT,
    //                         'solution' => (string) $vuln->SOLUTION,
    //                     ];
    //                 }
    //             }
    //         }

    //         dd($vulnDetails);
    //         // Dispatch job to import vulnerabilities
    //         // dispatch(new \App\Jobs\ImportQualysVulnJob($vulnDetails));
    //         // return true;

    //     } catch (\Exception $e) {
    //         dd($e);
    //         Log::error('Qualys authentication exception', ['error' => $e->getMessage()]);
    //         return null;
    //     }
    // }


    /**
     * Login and sync using Qualys API only (Basic Auth).
     * No GUI/cookie login — works for API-only users.
     */
    public function authenticate()
    {
        $check = $this->checkCredentials();
        if (!$check['ok']) {
            $msg = $check['message'];
            if (!empty($check['faq_link'])) {
                $msg .= ' ' . $check['faq_link'];
            }
            throw new \Exception($msg);
        }

        try {
            $scanListResponse = Http::withHeaders(['X-Requested-With' => 'Curl Sample'])
                ->withBasicAuth($this->username, $this->password)
                ->get($this->url('/api/2.0/fo/scan/'), [
                    'action' => 'list',
                    'state' => 'Finished',
                    'show_last' => 50,
                ]);

            if (!$scanListResponse->successful()) {
                throw new \Exception('Failed to list scans: ' . $scanListResponse->body());
            }

            $xml = @simplexml_load_string($scanListResponse->body());
            $scanRefs = [];
            if ($xml && isset($xml->RESPONSE->SCAN_LIST->SCAN)) {
                foreach ($xml->RESPONSE->SCAN_LIST->SCAN as $scan) {
                    $scanRefs[] = (string) $scan->REF;
                }
            }

            $qids = [];
            foreach ($scanRefs as $scanRef) {
                $fetchResponse = Http::withHeaders(['X-Requested-With' => 'Curl Sample'])
                    ->withBasicAuth($this->username, $this->password)
                    ->get($this->url('/api/2.0/fo/scan/'), [
                        'action' => 'fetch',
                        'scan_ref' => $scanRef,
                        'output_format' => 'json',
                    ]);

                if ($fetchResponse->successful()) {
                    $jsonData = $fetchResponse->json();
                    if (is_array($jsonData)) {
                        foreach ($jsonData as $item) {
                            if (!empty($item['qid'])) {
                                $qids[] = (string) $item['qid'];
                            }
                        }
                    }
                }
            }

            $qids = array_values(array_unique(array_filter($qids)));
            if (empty($qids)) {
                Log::info('Qualys sync: no QIDs from scans');
                return true;
            }

            $vulnDetails = [];
            $batchSize = 100;
            foreach (array_chunk($qids, $batchSize) as $batch) {
                $kbResponse = Http::withHeaders(['X-Requested-With' => 'Curl Sample'])
                    ->withBasicAuth($this->username, $this->password)
                    ->get($this->url('/api/2.0/fo/knowledge_base/vuln/'), [
                        'action' => 'list',
                        'ids' => implode(',', $batch),
                    ]);

                if (!$kbResponse->successful()) {
                    continue;
                }

                $xmlKB = @simplexml_load_string($kbResponse->body());
                if (!$xmlKB || !isset($xmlKB->RESPONSE->VULN_LIST->VULN)) {
                    continue;
                }

                foreach ($xmlKB->RESPONSE->VULN_LIST->VULN as $vuln) {
                    $qid = (string) $vuln->QID;
                    $vulnDetails[] = [
                        'title' => (string) $vuln->TITLE,
                        'qid' => $qid,
                        'severity' => (string) $vuln->SEVERITY_LEVEL,
                        'impact' => (string) ($vuln->IMPACT ?? ''),
                        'solution' => (string) ($vuln->SOLUTION ?? ''),
                    ];
                }
            }

            if (!empty($vulnDetails)) {
                dispatch(new \App\Jobs\ImportQualysVulnJob($vulnDetails));
            }

            return true;
        } catch (\Exception $e) {
            Log::error('Qualys sync exception', ['error' => $e->getMessage()]);
            throw $e;
        }
    }




    // public function getVulnerabilityCount()
    // {



    //      try {
    //     $from = 1;
    //     $to = 4;
    //     $baseUrl = 'https://qualysguard.qg1.apps.qualysksa.com/api/2.0/fo/asset/host/vm/detection/';
    //     $results = [];
    //     $currentIndex = 0;
    //     $lastId = 0; // Track the last processed ID
    //     $maxAttempts = 10; // Prevent infinite loops
    //     $attempts = 0;

    //     while ($currentIndex < $to && $attempts < $maxAttempts) {
    //         $attempts++;
    //     dump($baseUrl);

    //         // Build URL with pagination
    //         $urlParams = [
    //             'action' => 'list',
    //             'truncation_limit' => 1,
    //             'id_min' => $lastId + 1 // Always request records after the last one we processed
    //         ];

    //         $response = Http::withHeaders([
    //                 'X-Requested-With' => 'Curl Sample',
    //             ])
    //             ->withBasicAuth($this->username, $this->password)
    //             ->asForm()
    //             ->get($baseUrl, $urlParams);

    //         $xml = simplexml_load_string($response->body());

    //         // Check if we got valid data
    //         if (!isset($xml->RESPONSE->HOST_LIST->HOST)) {
    //             break; // No more records
    //         }

    //         $host = $xml->RESPONSE->HOST_LIST->HOST;
    //         $currentId = (int)$host->ID;

    //         // Only process if this is a new record
    //         if ($currentId > $lastId) {
    //             $lastId = $currentId;

    //             if ($currentIndex >= $from) {
    //                 $detections = [];
    //                 if (isset($host->DETECTION_LIST->DETECTION)) {
    //                     foreach ($host->DETECTION_LIST->DETECTION as $det) {
    //                         $detections[] = json_decode(json_encode($det), true);
    //                     }
    //                 }

    //                 $results[] = [
    //                     'host_id' => (string)$host->ID,
    //                     'ip' => (string)$host->IP,
    //                     'os' => (string)$host->OS,
    //                     'last_scan' => (string)$host->LAST_SCAN_DATETIME,
    //                     'detections' => $detections,
    //                 ];
    //             }

    //             $currentIndex++;
    //         } else {
    //             // ID didn't increase - we're stuck
    //             break;
    //         }
    //     }

    //     return $results;
    // } catch (\Exception $e) {
    //     return ['error' => $e->getMessage()];
    // }


    // }


    public function getVulnerabilityCount()
{
    try {
        $batchSize = 3;
        $baseUrl = $this->url('/api/2.0/fo/asset/host/vm/detection/');
        $lastId = 0;
        $maxAttempts = 3; // Safety limit for total records
        $attempts = 0;
        $batch = [];

        while ($attempts < $maxAttempts) {
            $attempts++;

            // Build URL with pagination
            $urlParams = [
                'action' => 'list',
                'truncation_limit' => 1,
                'id_min' => $lastId + 1
            ];

            $response = Http::withHeaders([
                'X-Requested-With' => 'Curl Sample',
            ])
            ->withBasicAuth($this->username, $this->password)
            ->asForm()
            ->get($baseUrl, $urlParams);

            $xml = simplexml_load_string($response->body());

            // Check if we got valid data
            if (!isset($xml->RESPONSE->HOST_LIST->HOST)) {
                break; // No more records
            }

            $host = $xml->RESPONSE->HOST_LIST->HOST;
            $currentId = (int)$host->ID;

            // Only process if this is a new record
            if ($currentId > $lastId) {
                $lastId = $currentId;

                $detections = [];
                if (isset($host->DETECTION_LIST->DETECTION)) {
                    foreach ($host->DETECTION_LIST->DETECTION as $det) {
                        $detections[] = json_decode(json_encode($det), true);
                    }
                }

                $batch[] = [
                    'host_id' => (string)$host->ID,
                    'ip' => (string)$host->IP,
                    'os' => (string)$host->OS,
                    'last_scan' => (string)$host->LAST_SCAN_DATETIME,
                    'detections' => $detections,
                ];

                // Dispatch batch when we reach batch size
                if (count($batch) >= $batchSize) {
                    // ProcessVulnerabilityBatch::dispatch($batch);
                    //    dispatch(new ProcessVulnerabilityBatch($batch))->delay(now()->addSeconds(10));
                    $batch = []; // Reset batch
                }
            } else {
                // ID didn't increase - we're stuck
                break;
            }
        }

        // Dispatch any remaining records in partial batch
        if (!empty($batch)) {
//    dispatch(new ProcessVulnerabilityBatch($batch))->delay(now()->addSeconds(10));
        }

        return ['success' => true, 'processed' => $attempts];
    } catch (\Exception $e) {
        return ['error' => $e->getMessage()];
    }
}


}
