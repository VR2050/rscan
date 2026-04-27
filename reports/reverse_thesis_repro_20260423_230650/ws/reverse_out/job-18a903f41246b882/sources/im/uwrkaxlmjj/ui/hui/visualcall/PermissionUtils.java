package im.uwrkaxlmjj.ui.hui.visualcall;

import android.app.Activity;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.util.Log;
import android.widget.Toast;
import androidx.appcompat.app.AlertDialog;
import androidx.core.app.ActivityCompat;
import im.uwrkaxlmjj.messenger.LocaleController;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PermissionUtils {
    public static final int CODE_ACCESS_COARSE_LOCATION = 6;
    public static final int CODE_ACCESS_FINE_LOCATION = 5;
    public static final int CODE_CALL_PHONE = 3;
    public static final int CODE_CAMERA = 4;
    public static final int CODE_GET_ACCOUNTS = 1;
    public static final int CODE_MULTI_PERMISSION = 100;
    public static final int CODE_READ_EXTERNAL_STORAGE = 7;
    public static final int CODE_READ_PHONE_STATE = 2;
    public static final int CODE_RECORD_AUDIO = 0;
    public static final int CODE_WRITE_EXTERNAL_STORAGE = 8;
    public static final String PERMISSION_ACCESS_FINE_LOCATION = "android.permission.ACCESS_FINE_LOCATION";
    public static final String PERMISSION_CAMERA = "android.permission.CAMERA";
    public static final String PERMISSION_READ_PHONE_STATE = "android.permission.READ_PHONE_STATE";
    public static final String PERMISSION_RECORD_AUDIO = "android.permission.RECORD_AUDIO";
    public static final String PERMISSION_WRITE_EXTERNAL_STORAGE = "android.permission.WRITE_EXTERNAL_STORAGE";
    public static final int REQUEST_CODE_SETTING = 100;
    private static final String TAG = PermissionUtils.class.getSimpleName();
    public static final String PERMISSION_GET_ACCOUNTS = "android.permission.GET_ACCOUNTS";
    public static final String PERMISSION_CALL_PHONE = "android.permission.CALL_PHONE";
    public static final String PERMISSION_ACCESS_COARSE_LOCATION = "android.permission.ACCESS_COARSE_LOCATION";
    public static final String PERMISSION_READ_EXTERNAL_STORAGE = "android.permission.READ_EXTERNAL_STORAGE";
    private static final String[] requestPermissions = {"android.permission.RECORD_AUDIO", PERMISSION_GET_ACCOUNTS, "android.permission.READ_PHONE_STATE", PERMISSION_CALL_PHONE, "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION", PERMISSION_ACCESS_COARSE_LOCATION, PERMISSION_READ_EXTERNAL_STORAGE, "android.permission.WRITE_EXTERNAL_STORAGE"};

    public interface PermissionGrant {
        void onPermissionCancel();

        void onPermissionGranted(int i);
    }

    public static void requestPermission(Activity activity, int requestCode, PermissionGrant permissionGrant) {
        if (activity == null) {
            return;
        }
        Log.i(TAG, "requestPermission requestCode:" + requestCode);
        if (requestCode >= 0) {
            String[] strArr = requestPermissions;
            if (requestCode < strArr.length) {
                String requestPermission = strArr[requestCode];
                try {
                    int checkSelfPermission = ActivityCompat.checkSelfPermission(activity, requestPermission);
                    if (checkSelfPermission != 0) {
                        Log.i(TAG, "ActivityCompat.checkSelfPermission != PackageManager.PERMISSION_GRANTED");
                        if (ActivityCompat.shouldShowRequestPermissionRationale(activity, requestPermission)) {
                            Log.i(TAG, "requestPermission shouldShowRequestPermissionRationale");
                            shouldShowRationale(activity, requestCode, requestPermission, permissionGrant);
                            return;
                        } else {
                            Log.d(TAG, "requestCameraPermission else");
                            ActivityCompat.requestPermissions(activity, new String[]{requestPermission}, requestCode);
                            return;
                        }
                    }
                    Log.d(TAG, "ActivityCompat.checkSelfPermission ==== PackageManager.PERMISSION_GRANTED");
                    Toast.makeText(activity, "opened:" + requestPermissions[requestCode], 0).show();
                    permissionGrant.onPermissionGranted(requestCode);
                    return;
                } catch (RuntimeException e) {
                    Toast.makeText(activity, "please open this permission", 0).show();
                    Log.e(TAG, "RuntimeException:" + e.getMessage());
                    return;
                }
            }
        }
        Log.w(TAG, "requestPermission illegal requestCode:" + requestCode);
    }

    private static void requestMultiResult(Activity activity, String[] permissions, int[] grantResults, PermissionGrant permissionGrant) {
        if (activity == null) {
            return;
        }
        Log.d(TAG, "onRequestPermissionsResult permissions length:" + permissions.length);
        Map<String, Integer> perms = new HashMap<>();
        ArrayList<String> notGranted = new ArrayList<>();
        for (int i = 0; i < permissions.length; i++) {
            Log.d(TAG, "permissions: [i]:" + i + ", permissions[i]" + permissions[i] + ",grantResults[i]:" + grantResults[i]);
            perms.put(permissions[i], Integer.valueOf(grantResults[i]));
            if (grantResults[i] != 0) {
                notGranted.add(permissions[i]);
            }
        }
        int i2 = notGranted.size();
        if (i2 == 0) {
            permissionGrant.onPermissionGranted(100);
        } else {
            openSettingActivity(activity, LocaleController.getString("visual_call_permission_tip", R.string.visual_call_permission_tip), null, permissionGrant);
        }
    }

    public static void requestMultiPermissions(final Activity activity, String[] permissions, final PermissionGrant grant) {
        List<String> permissionsList = getNoGrantedPermission(activity, permissions, false);
        final List<String> shouldRationalePermissionsList = getNoGrantedPermission(activity, permissions, true);
        if (permissionsList == null || shouldRationalePermissionsList == null) {
            return;
        }
        Log.d(TAG, "requestMultiPermissions permissionsList:" + permissionsList.size() + ",shouldRationalePermissionsList:" + shouldRationalePermissionsList.size());
        if (permissionsList.size() > 0) {
            ActivityCompat.requestPermissions(activity, (String[]) permissionsList.toArray(new String[permissionsList.size()]), 100);
            Log.d(TAG, "showMessageOKCancel requestPermissions");
        } else if (shouldRationalePermissionsList.size() > 0) {
            showMessageOKCancel(activity, LocaleController.getString("visual_call_permission_tip", R.string.visual_call_permission_tip), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$PermissionUtils$pZpGfpCese05NWtgEDlRfQcKhrE
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    PermissionUtils.lambda$requestMultiPermissions$0(activity, shouldRationalePermissionsList, dialogInterface, i);
                }
            }, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$PermissionUtils$LOwtC3_ygb2QEdfI27EfRGtDxxE
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    grant.onPermissionCancel();
                }
            });
        } else {
            grant.onPermissionGranted(100);
        }
    }

    static /* synthetic */ void lambda$requestMultiPermissions$0(Activity activity, List shouldRationalePermissionsList, DialogInterface dialog, int which) {
        ActivityCompat.requestPermissions(activity, (String[]) shouldRationalePermissionsList.toArray(new String[shouldRationalePermissionsList.size()]), 100);
        Log.d(TAG, "showMessageOKCancel requestPermissions");
    }

    private static void shouldShowRationale(final Activity activity, final int requestCode, final String requestPermission, final PermissionGrant permissionGrant) {
        showMessageOKCancel(activity, "Rationale: need to open under permission by yourself", new String[]{requestPermission}, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$PermissionUtils$fYEbIKA6kMaj5jVC8FVdJZbVUmk
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                PermissionUtils.lambda$shouldShowRationale$2(activity, requestPermission, requestCode, dialogInterface, i);
            }
        }, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$PermissionUtils$p7Bq_b0DLISv_-zDHnxHn7fHe2w
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                permissionGrant.onPermissionCancel();
            }
        });
    }

    static /* synthetic */ void lambda$shouldShowRationale$2(Activity activity, String requestPermission, int requestCode, DialogInterface dialog, int which) {
        ActivityCompat.requestPermissions(activity, new String[]{requestPermission}, requestCode);
        Log.d(TAG, "showMessageOKCancel requestPermissions:" + requestPermission);
    }

    private static void showMessageOKCancel(Activity context, String message, String[] permissions, DialogInterface.OnClickListener okListener, DialogInterface.OnClickListener cancelListener) {
        new AlertDialog.Builder(context).setTitle(message).setItems(permissions, (DialogInterface.OnClickListener) null).setPositiveButton(LocaleController.getString("OK", R.string.OK), okListener).setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), cancelListener).setCancelable(false).create().show();
    }

    public static void requestPermissionsResult(Activity activity, int requestCode, String[] permissions, int[] grantResults, PermissionGrant permissionGrant) {
        if (activity == null) {
            return;
        }
        Log.d(TAG, "requestPermissionsResult requestCode:" + requestCode);
        if (requestCode == 100) {
            requestMultiResult(activity, permissions, grantResults, permissionGrant);
            return;
        }
        if (requestCode < 0 || requestCode >= requestPermissions.length) {
            Log.w(TAG, "requestPermissionsResult illegal requestCode:" + requestCode);
            Toast.makeText(activity, "illegal requestCode:" + requestCode, 0).show();
            return;
        }
        Log.i(TAG, "onRequestPermissionsResult requestCode:" + requestCode + ",permissions:" + permissions.toString() + ",grantResults:" + grantResults.toString() + ",length:" + grantResults.length);
        if (grantResults.length == 1 && grantResults[0] == 0) {
            Log.i(TAG, "onRequestPermissionsResult PERMISSION_GRANTED");
            permissionGrant.onPermissionGranted(requestCode);
        } else {
            Log.i(TAG, "onRequestPermissionsResult PERMISSION NOT GRANTED");
            openSettingActivity(activity, "those permission need granted!", permissions, permissionGrant);
        }
    }

    private static void openSettingActivity(final Activity activity, String message, String[] permissions, final PermissionGrant permissionGrant) {
        showMessageOKCancel(activity, message, permissions, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$PermissionUtils$lcra_iQjn8P4hFvhEwCebs7qzTY
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                PermissionUtils.lambda$openSettingActivity$4(activity, dialogInterface, i);
            }
        }, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$PermissionUtils$iAQbfNLYR0NYFPWgrJFhKlq9BzU
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                permissionGrant.onPermissionCancel();
            }
        });
    }

    static /* synthetic */ void lambda$openSettingActivity$4(Activity activity, DialogInterface dialog, int which) {
        Intent intent = new Intent();
        intent.setAction("android.settings.APPLICATION_DETAILS_SETTINGS");
        Log.d(TAG, "getPackageName(): " + activity.getPackageName());
        Uri uri = Uri.fromParts("package", activity.getPackageName(), null);
        intent.setData(uri);
        activity.startActivityForResult(intent, 100);
    }

    public static ArrayList<String> getNoGrantedPermission(Activity activity, String[] permissions, boolean isShouldRationale) {
        ArrayList<String> noGrantedPermission = new ArrayList<>();
        for (String requestPermission : permissions) {
            try {
                int checkSelfPermission = ActivityCompat.checkSelfPermission(activity, requestPermission);
                if (checkSelfPermission != 0) {
                    Log.i(TAG, "getNoGrantedPermission ActivityCompat.checkSelfPermission != PackageManager.PERMISSION_GRANTED:" + requestPermission);
                    if (ActivityCompat.shouldShowRequestPermissionRationale(activity, requestPermission)) {
                        Log.d(TAG, "shouldShowRequestPermissionRationale if");
                        if (isShouldRationale) {
                            noGrantedPermission.add(requestPermission);
                        }
                    } else {
                        if (!isShouldRationale) {
                            noGrantedPermission.add(requestPermission);
                        }
                        Log.d(TAG, "shouldShowRequestPermissionRationale else");
                    }
                }
            } catch (RuntimeException e) {
                Toast.makeText(activity, "please open those permission", 0).show();
                Log.e(TAG, "RuntimeException:" + e.getMessage());
                return null;
            }
        }
        return noGrantedPermission;
    }
}
