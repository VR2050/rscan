package com.bjz.comm.net.premission;

import android.annotation.SuppressLint;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import com.bjz.comm.net.BuildVars;
import com.bjz.comm.net.R;
import java.util.ArrayList;
import java.util.List;
import pub.devrel.easypermissions.AppSettingsDialog;
import pub.devrel.easypermissions.EasyPermissions;

/* JADX INFO: loaded from: classes4.dex */
public class PermissionActivity extends AppCompatActivity implements EasyPermissions.PermissionCallbacks {
    private static final String TAG = "PermissionLog";
    private String[] permissions;
    private List<String> addTexts = new ArrayList();
    private int permissionSize = 0;
    private boolean isFirst = true;

    @SuppressLint({"HandlerLeak"})
    private Handler handler = new Handler() { // from class: com.bjz.comm.net.premission.PermissionActivity.1
        @Override // android.os.Handler
        public void handleMessage(Message msg) {
            super.handleMessage(msg);
            if (msg.what == 11) {
                PermissionActivity.this.onBackPressed();
            }
        }
    };

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (savedInstanceState != null) {
            this.permissions = savedInstanceState.getStringArray("permissions");
        }
        initPermission(getIntent());
    }

    private void initPermission(Intent intent) {
        if (this.permissions == null) {
            this.permissions = intent.getStringArrayExtra("permissions");
        }
        EasyPermissions.requestPermissions(this, getCurPermission(), 10, this.permissions);
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    protected void onResume() {
        super.onResume();
        if (BuildVars.DEBUG_VERSION) {
            Log.e(TAG, getClass().getSimpleName() + " ===> onResume");
        }
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        initPermission(intent);
    }

    @SuppressLint({"StringFormatInvalid"})
    private String getCurPermission() {
        this.addTexts.clear();
        this.permissionSize = 0;
        StringBuilder builder = new StringBuilder();
        for (String value : this.permissions) {
            String per = getPermission(value);
            if (!this.addTexts.contains(per)) {
                this.addTexts.add(per);
                builder.append(per);
                builder.append("-");
                this.permissionSize++;
            }
        }
        builder.delete(builder.length() - 1, builder.length());
        return String.format(getString(R.string.need_permission), builder.toString());
    }

    @SuppressLint({"StringFormatInvalid"})
    private String getListPermission(List<String> perms) {
        this.addTexts.clear();
        StringBuilder builder = new StringBuilder();
        for (String value : perms) {
            String per = getPermission(value);
            if (!this.addTexts.contains(per)) {
                this.addTexts.add(per);
                builder.append(per);
                builder.append("-");
            }
        }
        builder.delete(builder.length() - 1, builder.length());
        return String.format(getString(R.string.need_permission), builder.toString());
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:77:0x011a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private java.lang.String getPermission(java.lang.String r3) {
        /*
            Method dump skipped, instruction units count: 502
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.bjz.comm.net.premission.PermissionActivity.getPermission(java.lang.String):java.lang.String");
    }

    @Override // androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onSaveInstanceState(@NonNull Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putStringArray("permissions", this.permissions);
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        EasyPermissions.onRequestPermissionsResult(requestCode, permissions, grantResults, this);
    }

    @Override // pub.devrel.easypermissions.EasyPermissions.PermissionCallbacks
    public void onPermissionsGranted(int requestCode, @NonNull List<String> perms) {
        if (BuildVars.DEBUG_VERSION) {
            Log.e(TAG, getClass().getSimpleName() + " ===> onPermissionsGranted-成功" + perms.toString());
        }
        if (this.permissions.length == perms.size()) {
            PermissionManager.getInstance(this).requestPermissionSuccess();
            onBackPressed();
        } else {
            this.handler.sendEmptyMessageDelayed(11, 500L);
        }
    }

    @Override // pub.devrel.easypermissions.EasyPermissions.PermissionCallbacks
    public void onPermissionsDenied(int requestCode, @NonNull List<String> perms) {
        if (BuildVars.DEBUG_VERSION) {
            Log.e(TAG, getClass().getSimpleName() + " ===> onPermissionsDenied-失败" + perms.toString());
        }
        if (EasyPermissions.somePermissionPermanentlyDenied(this, perms) && this.isFirst) {
            this.isFirst = false;
            new AppSettingsDialog.Builder(this).setRationale(String.format(getString(R.string.permission_message), getListPermission(perms))).setPositiveButton(getString(R.string.insure)).setNegativeButton(getString(R.string.quit)).build().show();
        }
        PermissionManager.getInstance(this).requestPermissionFail();
        this.handler.removeCallbacksAndMessages(null);
        onBackPressed();
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    protected void onDestroy() {
        super.onDestroy();
        if (BuildVars.DEBUG_VERSION) {
            Log.e(TAG, getClass().getSimpleName() + " ===> onDestroy");
        }
    }
}
