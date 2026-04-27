package im.uwrkaxlmjj.tel;

import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.telecom.TelecomManager;
import android.telephony.TelephonyManager;
import kotlin.Metadata;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;

/* JADX INFO: compiled from: CallInterceptor.kt */
/* JADX INFO: loaded from: classes2.dex */
@Metadata(bv = {1, 0, 3}, d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0003\b\u0016\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\b\u0010\u0003\u001a\u00020\u0004H\u0003J\u0010\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0006\u001a\u00020\u0007H\u0002J\u0012\u0010\b\u001a\u0004\u0018\u00010\t2\u0006\u0010\n\u001a\u00020\u000bH\u0016J\b\u0010\f\u001a\u00020\u0004H\u0016J\b\u0010\r\u001a\u00020\u0004H\u0016J\"\u0010\u000e\u001a\u00020\u000f2\b\u0010\n\u001a\u0004\u0018\u00010\u000b2\u0006\u0010\u0010\u001a\u00020\u000f2\u0006\u0010\u0011\u001a\u00020\u000fH\u0016¨\u0006\u0012"}, d2 = {"Lim/uwrkaxlmjj/tel/CallApiBelow26And28Service;", "Landroid/app/Service;", "()V", "hangUpCall", "", "matchRule", "incomingNumber", "", "onBind", "Landroid/os/IBinder;", "intent", "Landroid/content/Intent;", "onCreate", "onDestroy", "onStartCommand", "", "flags", "startId", "HMessagesPrj_prodRelease"}, k = 1, mv = {1, 1, 16})
public class CallApiBelow26And28Service extends Service {
    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
    }

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        Intrinsics.checkParameterIsNotNull(intent, "intent");
        return null;
    }

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int flags, int startId) {
        String callState = intent != null ? intent.getStringExtra("callState") : null;
        if (Intrinsics.areEqual(callState, TelephonyManager.EXTRA_STATE_RINGING)) {
            String incomingNumber = intent != null ? intent.getStringExtra("incomingNumber") : null;
            if (incomingNumber != null) {
                String it = incomingNumber;
                matchRule(it);
                CallInterceptorKt.deleteIncomingCallLog(this, it);
            }
        }
        return super.onStartCommand(intent, flags, startId);
    }

    private final void matchRule(String incomingNumber) {
        hangUpCall();
    }

    private final void hangUpCall() {
        try {
            if (Build.VERSION.SDK_INT == 28) {
                Object systemService = getSystemService("telecom");
                if (systemService == null) {
                    throw new TypeCastException("null cannot be cast to non-null type android.telecom.TelecomManager");
                }
                TelecomManager telecomManager = (TelecomManager) systemService;
                telecomManager.endCall();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override // android.app.Service
    public void onDestroy() {
        super.onDestroy();
    }
}
