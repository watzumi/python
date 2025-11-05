python
#!/usr/bin/env python3
"""
Simple APK Analyzer untuk cek status login/verifikasi
Simpan file ini sebagai apk_analyzer.py
"""

import os
import re
import zipfile
import json
import subprocess
from pathlib import Path

class APKAnalyzer:
    def __init__(self):
        self.results = {}
    
    def extract_apk(self, apk_path, output_dir="extracted_apk"):
        """Ekstrak file APK"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(output_dir)
            return True
        except Exception as e:
            print(f"Error extracting APK: {e}")
            return False
    
    def analyze_manifest(self, extracted_path):
        """Analisis AndroidManifest.xml"""
        manifest_path = os.path.join(extracted_path, "AndroidManifest.xml")
        if os.path.exists(manifest_path):
            print("✓ AndroidManifest.xml ditemukan")
            
            # Cari permission terkait auth
            auth_permissions = [
                "android.permission.INTERNET",
                "android.permission.READ_PHONE_STATE",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS"
            ]
            
            with open(manifest_path, 'r', errors='ignore') as f:
                content = f.read()
                for perm in auth_permissions:
                    if perm in content:
                        print(f"  - Permission ditemukan: {perm}")
    
    def search_auth_patterns(self, extracted_path):
        """Cari pattern kode terkait authentication"""
        patterns = {
            'login_status': [
                r'isLoggedIn',
                r'isLoggedIn\(\)',
                r'getBoolean\(\"is_logged_in\"',
                r'isAuthenticated',
                r'loginStatus'
            ],
            'verification': [
                r'isVerified',
                r'isVerified\(\)',
                r'phoneVerified',
                r'verifyPhone',
                r'verificationStatus'
            ],
            'shared_prefs': [
                r'SharedPreferences',
                r'getBoolean',
                r'getString',
                r'edit\(\).putBoolean'
            ],
            'firebase_auth': [
                r'FirebaseAuth',
                r'getCurrentUser',
                r'signInWithPhoneNumber',
                r'verifyPhoneNumber'
            ]
        }
        
        print("\n🔍 Mencari pattern authentication...")
        
        for category, pattern_list in patterns.items():
            print(f"\n📂 {category.upper()}:")
            for pattern in pattern_list:
                cmd = f'grep -r -n "{pattern}" "{extracted_path}" --include="*.smali" --include="*.xml" 2>/dev/null | head -5'
                result = subprocess.getoutput(cmd)
                if result:
                    print(f"  Pattern: {pattern}")
                    for line in result.split('\n')[:3]:  # Tampilkan 3 hasil pertama
                        if line:
                            print(f"    → {line}")
    
    def check_network_endpoints(self, extracted_path):
        """Cari endpoint API untuk login/verifikasi"""
        print("\n🌐 Mencari endpoint API...")
        
        url_patterns = [
            r'https?://[^\s"<>]+/login',
            r'https?://[^\s"<>]+/verify',
            r'https?://[^\s"<>]+/auth',
            r'https?://[^\s"<>]+/validation',
            r'https?://[^\s"<>]+/phone'
        ]
        
        for pattern in url_patterns:
            cmd = f'grep -r -o -E "{pattern}" "{extracted_path}" 2>/dev/null | head -3'
            result = subprocess.getoutput(cmd)
            if result:
                print(f"  Endpoint ditemukan:")
                for url in result.split('\n'):
                    if url:
                        print(f"    🔗 {url}")
    
    def analyze(self, apk_path):
        """Main analysis function"""
        print(f"🔎 Analyzing APK: {apk_path}")
        
        if not os.path.exists(apk_path):
            print("❌ File APK tidak ditemukan!")
            return
        
        extracted_dir = "temp_extracted"
        
        # Step 1: Extract APK
        print("📦 Mengekstrak APK...")
        if not self.extract_apk(apk_path, extracted_dir):
            return
        
        # Step 2: Analyze components
        self.analyze_manifest(extracted_dir)
        self.search_auth_patterns(extracted_dir)
        self.check_network_endpoints(extracted_dir)
        
        # Cleanup
        import shutil
        shutil.rmtree(extracted_dir, ignore_errors=True)
        
        print("\n✅ Analisis selesai!")

# Cara penggunaan
if __name__ == "__main__":
    analyzer = APKAnalyzer()
    
    # Ganti dengan path APK yang ingin dianalisis
    apk_file = "example.apk"  # ← GANTI DENGAN APK ANDA
    
    if os.path.exists(apk_file):
        analyzer.analyze(apk_file)
    else:
        print("❌ File APK tidak ditemukan!")
        print("💡 Cara penggunaan:")
        print("   1. Simpan file APK di folder yang sama dengan script ini")
        print("   2. Ganti 'example.apk' dengan nama file APK Anda")
        print("   3. Jalankan: python apk_analyzer.py")
```

2. Script Deteksi Sederhana untuk Aplikasi Android (File: AuthChecker.java)

```java
// Simpan sebagai AuthChecker.java
// Untuk digunakan dalam project Android Studio

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

public class AuthChecker {
    private static final String TAG = "AuthChecker";
    private SharedPreferences sharedPreferences;
    
    public AuthChecker(Context context) {
        sharedPreferences = context.getSharedPreferences("auth_prefs", Context.MODE_PRIVATE);
    }
    
    // Cek status login
    public boolean isUserLoggedIn() {
        return sharedPreferences.getBoolean("is_logged_in", false);
    }
    
    // Cek status verifikasi
    public boolean isPhoneVerified() {
        return sharedPreferences.getBoolean("is_verified", false);
    }
    
    // Simpan status login
    public void setLoggedIn(boolean status) {
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putBoolean("is_logged_in", status);
        editor.apply();
        Log.d(TAG, "Login status set to: " + status);
    }
    
    // Simpan status verifikasi
    public void setVerified(boolean status) {
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putBoolean("is_verified", status);
        editor.apply();
        Log.d(TAG, "Verification status set to: " + status);
    }
    
    // Get user info
    public String getPhoneNumber() {
        return sharedPreferences.getString("phone_number", "");
    }
    
    // Clear all data (logout)
    public void clearAuthData() {
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.clear();
        editor.apply();
        Log.d(TAG, "All auth data cleared");
    }
    
    // Print semua status
    public void printAuthStatus() {
        Log.i(TAG, "=== AUTH STATUS ===");
        Log.i(TAG, "Logged In: " + isUserLoggedIn());
        Log.i(TAG, "Verified: " + isPhoneVerified());
        Log.i(TAG, "Phone: " + getPhoneNumber());
        Log.i(TAG, "===================");
    }
}
```

3. Cara Menjalankan:

Untuk Script Python:

```bash
# Simpan script sebagai apk_analyzer.py
# Install requirements (jika perlu)
pip install pathlib

# Jalankan script
python apk_analyzer.py
```

Untuk Android Code:

1. Buat project baru di Android Studio
2. Copy AuthChecker.java ke folder app/src/main/java/your-package/
3. Gunakan dalam Activity:

```java
public class MainActivity extends AppCompatActivity {
    private AuthChecker authChecker;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        authChecker = new AuthChecker(this);
        
        // Cek status
        if (authChecker.isUserLoggedIn()) {
            // User sudah login
            Log.d("STATUS", "User sudah login");
        } else {
            // User belum login
            Log.d("STATUS", "User belum login");
        }
        
        // Print semua status
        authChecker.printAuthStatus();
    }
}
```

4. File Struktur Project:

```
project-folder/
├── apk_analyzer.py          # Script analisis APK
├── example.apk              # APK target (ganti dengan APK Anda)
├── android-project/         # Project Android Studio
│   ├── app/
│   │   └── src/main/java/
│   │       └── com/example/
│   │           ├── AuthChecker.java
│   │           └── MainActivity.java
