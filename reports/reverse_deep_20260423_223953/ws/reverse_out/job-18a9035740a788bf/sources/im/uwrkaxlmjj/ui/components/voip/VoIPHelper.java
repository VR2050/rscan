package im.uwrkaxlmjj.ui.components.voip;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.DownloadController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.voip.VoIPService;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.VoIPActivity;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.CheckBoxCell;
import im.uwrkaxlmjj.ui.cells.TextCheckCell;
import im.uwrkaxlmjj.ui.components.BetterRatingView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.components.voip.VoIPHelper;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Set;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class VoIPHelper {
    private static final int VOIP_SUPPORT_ID = 4244000;
    public static long lastCallTime = 0;

    public static void startCall(TLRPC.User user, final Activity activity, TLRPC.UserFull userFull) {
        int i;
        String str;
        int i2;
        String str2;
        if (userFull != null && userFull.phone_calls_private) {
            new AlertDialog.Builder(activity).setTitle(LocaleController.getString("VoipFailed", R.string.VoipFailed)).setMessage(AndroidUtilities.replaceTags(LocaleController.formatString("CallNotAvailable", R.string.CallNotAvailable, ContactsController.formatName(user.first_name, user.last_name)))).setPositiveButton(LocaleController.getString("OK", R.string.OK), null).show();
            return;
        }
        if (ConnectionsManager.getInstance(UserConfig.selectedAccount).getConnectionState() != 3) {
            boolean isAirplaneMode = Settings.System.getInt(activity.getContentResolver(), "airplane_mode_on", 0) != 0;
            AlertDialog.Builder builder = new AlertDialog.Builder(activity);
            if (isAirplaneMode) {
                i = R.string.VoipOfflineAirplaneTitle;
                str = "VoipOfflineAirplaneTitle";
            } else {
                i = R.string.VoipOfflineTitle;
                str = "VoipOfflineTitle";
            }
            AlertDialog.Builder title = builder.setTitle(LocaleController.getString(str, i));
            if (isAirplaneMode) {
                i2 = R.string.VoipOfflineAirplane;
                str2 = "VoipOfflineAirplane";
            } else {
                i2 = R.string.VoipOffline;
                str2 = "VoipOffline";
            }
            AlertDialog.Builder bldr = title.setMessage(LocaleController.getString(str2, i2)).setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            if (isAirplaneMode) {
                final Intent settingsIntent = new Intent("android.settings.AIRPLANE_MODE_SETTINGS");
                if (settingsIntent.resolveActivity(activity.getPackageManager()) != null) {
                    bldr.setNeutralButton(LocaleController.getString("VoipOfflineOpenSettings", R.string.VoipOfflineOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.voip.-$$Lambda$VoIPHelper$hGEMLdB0y0LYLc1GeLUzPRTmiEo
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i3) {
                            activity.startActivity(settingsIntent);
                        }
                    });
                }
            }
            bldr.show();
            return;
        }
        if (Build.VERSION.SDK_INT >= 23 && activity.checkSelfPermission("android.permission.RECORD_AUDIO") != 0) {
            activity.requestPermissions(new String[]{"android.permission.RECORD_AUDIO"}, 101);
        } else {
            initiateCall(user, activity);
        }
    }

    private static void initiateCall(final TLRPC.User user, final Activity activity) {
        if (activity == null || user == null) {
            return;
        }
        if (VoIPService.getSharedInstance() != null) {
            TLRPC.User callUser = VoIPService.getSharedInstance().getUser();
            if (callUser.id != user.id) {
                new AlertDialog.Builder(activity).setTitle(LocaleController.getString("VoipOngoingAlertTitle", R.string.VoipOngoingAlertTitle)).setMessage(AndroidUtilities.replaceTags(LocaleController.formatString("VoipOngoingAlert", R.string.VoipOngoingAlert, ContactsController.formatName(callUser.first_name, callUser.last_name), ContactsController.formatName(user.first_name, user.last_name)))).setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.voip.-$$Lambda$VoIPHelper$ypagprlw0PrRRLg39aR7BcqJCV4
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        VoIPHelper.lambda$initiateCall$2(user, activity, dialogInterface, i);
                    }
                }).setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null).show();
                return;
            } else {
                activity.startActivity(new Intent(activity, (Class<?>) VoIPActivity.class).addFlags(C.ENCODING_PCM_MU_LAW));
                return;
            }
        }
        if (VoIPService.callIShouldHavePutIntoIntent == null) {
            doInitiateCall(user, activity);
        }
    }

    static /* synthetic */ void lambda$initiateCall$2(final TLRPC.User user, final Activity activity, DialogInterface dialog, int which) {
        if (VoIPService.getSharedInstance() != null) {
            VoIPService.getSharedInstance().hangUp(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.voip.-$$Lambda$VoIPHelper$FZM85vZGmCEBJqHrik9Kz2nvxaM
                @Override // java.lang.Runnable
                public final void run() {
                    VoIPHelper.doInitiateCall(user, activity);
                }
            });
        } else {
            doInitiateCall(user, activity);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void doInitiateCall(TLRPC.User user, Activity activity) {
        if (activity == null || user == null || System.currentTimeMillis() - lastCallTime < AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS) {
            return;
        }
        lastCallTime = System.currentTimeMillis();
        Intent intent = new Intent(activity, (Class<?>) VoIPService.class);
        intent.putExtra("user_id", user.id);
        intent.putExtra("is_outgoing", true);
        intent.putExtra("start_incall_activity", true);
        intent.putExtra("account", UserConfig.selectedAccount);
        try {
            activity.startService(intent);
        } catch (Throwable e) {
            FileLog.e(e);
        }
    }

    public static void permissionDenied(final Activity activity, final Runnable onFinish) {
        if (!activity.shouldShowRequestPermissionRationale("android.permission.RECORD_AUDIO")) {
            AlertDialog dlg = new AlertDialog.Builder(activity).setTitle(LocaleController.getString("AppName", R.string.AppName)).setMessage(LocaleController.getString("VoipNeedMicPermission", R.string.VoipNeedMicPermission)).setPositiveButton(LocaleController.getString("OK", R.string.OK), null).setNegativeButton(LocaleController.getString("Settings", R.string.Settings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.voip.-$$Lambda$VoIPHelper$FSPupSbD5DajoLvHI78yYv3vVUQ
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    VoIPHelper.lambda$permissionDenied$3(activity, dialogInterface, i);
                }
            }).show();
            dlg.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.components.voip.-$$Lambda$VoIPHelper$geqBVmgYG6hUkaa_AgRGMhfXi_s
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    VoIPHelper.lambda$permissionDenied$4(onFinish, dialogInterface);
                }
            });
        }
    }

    static /* synthetic */ void lambda$permissionDenied$3(Activity activity, DialogInterface dialog, int which) {
        Intent intent = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
        Uri uri = Uri.fromParts("package", activity.getPackageName(), null);
        intent.setData(uri);
        activity.startActivity(intent);
    }

    static /* synthetic */ void lambda$permissionDenied$4(Runnable onFinish, DialogInterface dialog) {
        if (onFinish != null) {
            onFinish.run();
        }
    }

    public static File getLogsDir() {
        File logsDir = new File(ApplicationLoader.applicationContext.getCacheDir(), "voip_logs");
        if (!logsDir.exists()) {
            logsDir.mkdirs();
        }
        return logsDir;
    }

    public static boolean canRateCall(TLRPC.TL_messageActionPhoneCall call) {
        if (!(call.reason instanceof TLRPC.TL_phoneCallDiscardReasonBusy) && !(call.reason instanceof TLRPC.TL_phoneCallDiscardReasonMissed)) {
            SharedPreferences prefs = MessagesController.getNotificationsSettings(UserConfig.selectedAccount);
            Set<String> hashes = prefs.getStringSet("calls_access_hashes", Collections.EMPTY_SET);
            for (String hash : hashes) {
                String[] d = hash.split(" ");
                if (d.length >= 2) {
                    if (d[0].equals(call.call_id + "")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public static void showRateAlert(Context context, TLRPC.TL_messageActionPhoneCall call) {
        SharedPreferences prefs = MessagesController.getNotificationsSettings(UserConfig.selectedAccount);
        Set<String> hashes = prefs.getStringSet("calls_access_hashes", Collections.EMPTY_SET);
        for (String hash : hashes) {
            String[] d = hash.split(" ");
            if (d.length >= 2) {
                if (d[0].equals(call.call_id + "")) {
                    try {
                        long accessHash = Long.parseLong(d[1]);
                        showRateAlert(context, null, call.call_id, accessHash, UserConfig.selectedAccount, true);
                        return;
                    } catch (Exception e) {
                        return;
                    }
                }
            }
        }
    }

    public static void showRateAlert(final Context context, final Runnable onDismiss, long callID, long accessHash, int account, boolean userInitiative) {
        final File log = getLogFile(callID);
        int i = 1;
        boolean z = false;
        int[] page = {0};
        LinearLayout linearLayout = new LinearLayout(context);
        linearLayout.setOrientation(1);
        int pad = AndroidUtilities.dp(16.0f);
        linearLayout.setPadding(pad, pad, pad, 0);
        TextView text = new TextView(context);
        text.setTextSize(2, 16.0f);
        text.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        text.setGravity(17);
        text.setText(LocaleController.getString("VoipRateCallAlert", R.string.VoipRateCallAlert));
        linearLayout.addView(text);
        BetterRatingView bar = new BetterRatingView(context);
        linearLayout.addView(bar, LayoutHelper.createLinear(-2, -2, 1, 0, 16, 0, 0));
        LinearLayout problemsWrap = new LinearLayout(context);
        problemsWrap.setOrientation(1);
        View.OnClickListener problemCheckboxClickListener = new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.voip.VoIPHelper.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                CheckBoxCell check = (CheckBoxCell) v;
                check.setChecked(!check.isChecked(), true);
            }
        };
        String[] problems = {"echo", "noise", "interruptions", "distorted_speech", "silent_local", "silent_remote", "dropped"};
        int i2 = 0;
        while (i2 < problems.length) {
            CheckBoxCell check = new CheckBoxCell(context, i);
            check.setClipToPadding(z);
            check.setTag(problems[i2]);
            String label = null;
            switch (i2) {
                case 0:
                    label = LocaleController.getString("RateCallEcho", R.string.RateCallEcho);
                    break;
                case 1:
                    label = LocaleController.getString("RateCallNoise", R.string.RateCallNoise);
                    break;
                case 2:
                    label = LocaleController.getString("RateCallInterruptions", R.string.RateCallInterruptions);
                    break;
                case 3:
                    label = LocaleController.getString("RateCallDistorted", R.string.RateCallDistorted);
                    break;
                case 4:
                    label = LocaleController.getString("RateCallSilentLocal", R.string.RateCallSilentLocal);
                    break;
                case 5:
                    label = LocaleController.getString("RateCallSilentRemote", R.string.RateCallSilentRemote);
                    break;
                case 6:
                    label = LocaleController.getString("RateCallDropped", R.string.RateCallDropped);
                    break;
            }
            check.setText(label, null, false, false);
            check.setOnClickListener(problemCheckboxClickListener);
            check.setTag(problems[i2]);
            problemsWrap.addView(check);
            i2++;
            i = 1;
            z = false;
        }
        linearLayout.addView(problemsWrap, LayoutHelper.createLinear(-1, -2, -8.0f, 0.0f, -8.0f, 0.0f));
        problemsWrap.setVisibility(8);
        EditText commentBox = new EditText(context);
        commentBox.setHint(LocaleController.getString("VoipFeedbackCommentHint", R.string.VoipFeedbackCommentHint));
        commentBox.setInputType(147457);
        commentBox.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        commentBox.setHintTextColor(Theme.getColor(Theme.key_dialogTextHint));
        commentBox.setBackgroundDrawable(Theme.createEditTextDrawable(context, true));
        commentBox.setPadding(0, AndroidUtilities.dp(4.0f), 0, AndroidUtilities.dp(4.0f));
        commentBox.setTextSize(18.0f);
        commentBox.setVisibility(8);
        linearLayout.addView(commentBox, LayoutHelper.createLinear(-1, -2, 8.0f, 8.0f, 8.0f, 0.0f));
        final boolean[] includeLogs = {true};
        final CheckBoxCell checkbox = new CheckBoxCell(context, 1);
        View.OnClickListener checkClickListener = new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.voip.VoIPHelper.2
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                boolean[] zArr = includeLogs;
                zArr[0] = !zArr[0];
                checkbox.setChecked(zArr[0], true);
            }
        };
        checkbox.setText(LocaleController.getString("CallReportIncludeLogs", R.string.CallReportIncludeLogs), null, true, false);
        checkbox.setClipToPadding(false);
        checkbox.setOnClickListener(checkClickListener);
        linearLayout.addView(checkbox, LayoutHelper.createLinear(-1, -2, -8.0f, 0.0f, -8.0f, 0.0f));
        TextView logsText = new TextView(context);
        logsText.setTextSize(2, 14.0f);
        logsText.setTextColor(Theme.getColor(Theme.key_dialogTextGray3));
        logsText.setText(LocaleController.getString("CallReportLogsExplain", R.string.CallReportLogsExplain));
        logsText.setPadding(AndroidUtilities.dp(8.0f), 0, AndroidUtilities.dp(8.0f), 0);
        logsText.setOnClickListener(checkClickListener);
        linearLayout.addView(logsText);
        checkbox.setVisibility(8);
        logsText.setVisibility(8);
        if (!log.exists()) {
            includeLogs[0] = false;
        }
        AlertDialog alert = new AlertDialog.Builder(context).setTitle(LocaleController.getString("CallMessageReportProblem", R.string.CallMessageReportProblem)).setView(linearLayout).setPositiveButton(LocaleController.getString("Send", R.string.Send), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.voip.VoIPHelper.4
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialog, int which) {
            }
        }).setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null).setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.components.voip.VoIPHelper.3
            @Override // android.content.DialogInterface.OnDismissListener
            public void onDismiss(DialogInterface dialog) {
                Runnable runnable = onDismiss;
                if (runnable != null) {
                    runnable.run();
                }
            }
        }).create();
        if (BuildVars.DEBUG_VERSION && log.exists()) {
            alert.setNeutralButton("Send log", new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.voip.VoIPHelper.5
                @Override // android.content.DialogInterface.OnClickListener
                public void onClick(DialogInterface dialog, int which) {
                    Intent intent = new Intent(context, (Class<?>) LaunchActivity.class);
                    intent.setAction("android.intent.action.SEND");
                    intent.putExtra("android.intent.extra.STREAM", Uri.fromFile(log));
                    context.startActivity(intent);
                }
            });
        }
        alert.show();
        alert.getWindow().setSoftInputMode(3);
        final View btn = alert.getButton(-1);
        btn.setEnabled(false);
        bar.setOnRatingChangeListener(new BetterRatingView.OnRatingChangeListener() { // from class: im.uwrkaxlmjj.ui.components.voip.VoIPHelper.6
            @Override // im.uwrkaxlmjj.ui.components.BetterRatingView.OnRatingChangeListener
            public void onRatingChanged(int rating) {
                int i3;
                String str;
                btn.setEnabled(rating > 0);
                TextView textView = (TextView) btn;
                if (rating < 4) {
                    i3 = R.string.Next;
                    str = "Next";
                } else {
                    i3 = R.string.Send;
                    str = "Send";
                }
                textView.setText(LocaleController.getString(str, i3).toUpperCase());
            }
        });
        btn.setOnClickListener(new AnonymousClass7(bar, page, problemsWrap, commentBox, includeLogs, accessHash, callID, userInitiative, account, log, alert, text, checkbox, logsText, btn));
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.voip.VoIPHelper$7, reason: invalid class name */
    static class AnonymousClass7 implements View.OnClickListener {
        final /* synthetic */ long val$accessHash;
        final /* synthetic */ int val$account;
        final /* synthetic */ AlertDialog val$alert;
        final /* synthetic */ BetterRatingView val$bar;
        final /* synthetic */ View val$btn;
        final /* synthetic */ long val$callID;
        final /* synthetic */ CheckBoxCell val$checkbox;
        final /* synthetic */ EditText val$commentBox;
        final /* synthetic */ boolean[] val$includeLogs;
        final /* synthetic */ File val$log;
        final /* synthetic */ TextView val$logsText;
        final /* synthetic */ int[] val$page;
        final /* synthetic */ LinearLayout val$problemsWrap;
        final /* synthetic */ TextView val$text;
        final /* synthetic */ boolean val$userInitiative;

        AnonymousClass7(BetterRatingView betterRatingView, int[] iArr, LinearLayout linearLayout, EditText editText, boolean[] zArr, long j, long j2, boolean z, int i, File file, AlertDialog alertDialog, TextView textView, CheckBoxCell checkBoxCell, TextView textView2, View view) {
            this.val$bar = betterRatingView;
            this.val$page = iArr;
            this.val$problemsWrap = linearLayout;
            this.val$commentBox = editText;
            this.val$includeLogs = zArr;
            this.val$accessHash = j;
            this.val$callID = j2;
            this.val$userInitiative = z;
            this.val$account = i;
            this.val$log = file;
            this.val$alert = alertDialog;
            this.val$text = textView;
            this.val$checkbox = checkBoxCell;
            this.val$logsText = textView2;
            this.val$btn = view;
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View v) {
            int rating = this.val$bar.getRating();
            if (rating < 4) {
                int[] iArr = this.val$page;
                if (iArr[0] != 1) {
                    iArr[0] = 1;
                    this.val$bar.setVisibility(8);
                    this.val$text.setVisibility(8);
                    this.val$alert.setTitle(LocaleController.getString("CallReportHint", R.string.CallReportHint));
                    this.val$commentBox.setVisibility(0);
                    if (this.val$log.exists()) {
                        this.val$checkbox.setVisibility(0);
                        this.val$logsText.setVisibility(0);
                    }
                    this.val$problemsWrap.setVisibility(0);
                    ((TextView) this.val$btn).setText(LocaleController.getString("Send", R.string.Send).toUpperCase());
                    return;
                }
            }
            final int currentAccount = UserConfig.selectedAccount;
            final TLRPC.TL_phone_setCallRating req = new TLRPC.TL_phone_setCallRating();
            req.rating = this.val$bar.getRating();
            final ArrayList<String> problemTags = new ArrayList<>();
            for (int i = 0; i < this.val$problemsWrap.getChildCount(); i++) {
                CheckBoxCell check = (CheckBoxCell) this.val$problemsWrap.getChildAt(i);
                if (check.isChecked()) {
                    problemTags.add("#" + check.getTag());
                }
            }
            int i2 = req.rating;
            if (i2 < 5) {
                req.comment = this.val$commentBox.getText().toString();
            } else {
                req.comment = "";
            }
            if (!problemTags.isEmpty() && !this.val$includeLogs[0]) {
                req.comment += " " + TextUtils.join(" ", problemTags);
            }
            req.peer = new TLRPC.TL_inputPhoneCall();
            req.peer.access_hash = this.val$accessHash;
            req.peer.id = this.val$callID;
            req.user_initiative = this.val$userInitiative;
            ConnectionsManager connectionsManager = ConnectionsManager.getInstance(this.val$account);
            final boolean[] zArr = this.val$includeLogs;
            final File file = this.val$log;
            connectionsManager.sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.components.voip.-$$Lambda$VoIPHelper$7$DdiSL2Sk7bUZvRvTlrYZnuB8uko
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    VoIPHelper.AnonymousClass7.lambda$onClick$0(currentAccount, zArr, file, req, problemTags, tLObject, tL_error);
                }
            });
            this.val$alert.dismiss();
        }

        static /* synthetic */ void lambda$onClick$0(int currentAccount, boolean[] includeLogs, File log, TLRPC.TL_phone_setCallRating req, ArrayList problemTags, TLObject response, TLRPC.TL_error error) {
            if (response instanceof TLRPC.TL_updates) {
                TLRPC.TL_updates updates = (TLRPC.TL_updates) response;
                MessagesController.getInstance(currentAccount).processUpdates(updates, false);
            }
            if (includeLogs[0] && log.exists()) {
                if (req.rating < 4) {
                    AccountInstance accountInstance = AccountInstance.getInstance(UserConfig.selectedAccount);
                    SendMessagesHelper.prepareSendingDocument(accountInstance, log.getAbsolutePath(), log.getAbsolutePath(), null, TextUtils.join(" ", problemTags), "text/plain", 4244000L, null, null, null, true, 0);
                    ToastUtils.show(R.string.CallReportSent);
                }
            }
        }
    }

    private static File getLogFile(long callID) {
        File debugLogsDir;
        String[] logs;
        if (BuildVars.DEBUG_VERSION && (logs = (debugLogsDir = new File(ApplicationLoader.applicationContext.getExternalFilesDir(null), "logs")).list()) != null) {
            for (String log : logs) {
                if (log.endsWith("voip" + callID + ".txt")) {
                    return new File(debugLogsDir, log);
                }
            }
        }
        return new File(getLogsDir(), callID + ".log");
    }

    public static void showCallDebugSettings(Context context) {
        final SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        LinearLayout ll = new LinearLayout(context);
        ll.setOrientation(1);
        TextView warning = new TextView(context);
        warning.setTextSize(1, 15.0f);
        warning.setText("Please only change these settings if you know exactly what they do.");
        warning.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        ll.addView(warning, LayoutHelper.createLinear(-1, -2, 16.0f, 8.0f, 16.0f, 8.0f));
        final TextCheckCell tcpCell = new TextCheckCell(context);
        tcpCell.setTextAndCheck("Force TCP", preferences.getBoolean("dbg_force_tcp_in_calls", false), false);
        tcpCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.voip.VoIPHelper.8
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                boolean force = preferences.getBoolean("dbg_force_tcp_in_calls", false);
                SharedPreferences.Editor editor = preferences.edit();
                editor.putBoolean("dbg_force_tcp_in_calls", !force);
                editor.commit();
                tcpCell.setChecked(!force);
            }
        });
        ll.addView(tcpCell);
        if (BuildVars.DEBUG_VERSION && BuildVars.LOGS_ENABLED) {
            final TextCheckCell dumpCell = new TextCheckCell(context);
            dumpCell.setTextAndCheck("Dump detailed stats", preferences.getBoolean("dbg_dump_call_stats", false), false);
            dumpCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.voip.VoIPHelper.9
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    boolean force = preferences.getBoolean("dbg_dump_call_stats", false);
                    SharedPreferences.Editor editor = preferences.edit();
                    editor.putBoolean("dbg_dump_call_stats", !force);
                    editor.commit();
                    dumpCell.setChecked(!force);
                }
            });
            ll.addView(dumpCell);
        }
        if (Build.VERSION.SDK_INT >= 26) {
            final TextCheckCell connectionServiceCell = new TextCheckCell(context);
            connectionServiceCell.setTextAndCheck("Enable ConnectionService", preferences.getBoolean("dbg_force_connection_service", false), false);
            connectionServiceCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.voip.VoIPHelper.10
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    boolean force = preferences.getBoolean("dbg_force_connection_service", false);
                    SharedPreferences.Editor editor = preferences.edit();
                    editor.putBoolean("dbg_force_connection_service", !force);
                    editor.commit();
                    connectionServiceCell.setChecked(!force);
                }
            });
            ll.addView(connectionServiceCell);
        }
        new AlertDialog.Builder(context).setTitle(LocaleController.getString("DebugMenuCallSettings", R.string.DebugMenuCallSettings)).setView(ll).show();
    }

    public static int getDataSavingDefault() {
        boolean low = DownloadController.getInstance(0).lowPreset.lessCallData;
        boolean medium = DownloadController.getInstance(0).mediumPreset.lessCallData;
        boolean high = DownloadController.getInstance(0).highPreset.lessCallData;
        if (!low && !medium && !high) {
            return 0;
        }
        if (low && !medium && !high) {
            return 3;
        }
        if (low && medium && !high) {
            return 1;
        }
        if (low && medium && high) {
            return 2;
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.w("Invalid call data saving preset configuration: " + low + "/" + medium + "/" + high);
        }
        return 0;
    }
}
