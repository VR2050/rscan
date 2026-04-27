package im.uwrkaxlmjj.ui.settings;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.media.Ringtone;
import android.media.RingtoneManager;
import android.net.Uri;
import android.os.Parcelable;
import android.provider.Settings;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationsController;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.NotificationsSettingsActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.MrySwitch;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class NoticeAndSoundSettingActivity extends BaseFragment {
    private boolean reseting = false;
    private ArrayList<NotificationsSettingsActivity.NotificationException> exceptionUsers = null;
    private ArrayList<NotificationsSettingsActivity.NotificationException> exceptionChats = null;
    private ArrayList<NotificationsSettingsActivity.NotificationException> exceptionChannels = null;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        MessagesController.getInstance(this.currentAccount).loadSignUpNotificationsSettings();
        loadExceptions();
        return super.onFragmentCreate();
    }

    private void loadExceptions() {
        MessagesStorage.getInstance(this.currentAccount).getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$xMV4IMg3JCjoRRD5Qj2UqtXqTIA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadExceptions$1$NoticeAndSoundSettingActivity();
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:117:0x0320  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x033b A[LOOP:3: B:123:0x0339->B:124:0x033b, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:127:0x0353  */
    /* JADX WARN: Removed duplicated region for block: B:143:0x028d A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:80:0x02a7  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x02af A[Catch: Exception -> 0x02c4, TRY_LEAVE, TryCatch #3 {Exception -> 0x02c4, blocks: (B:81:0x02a9, B:83:0x02af), top: B:141:0x02a9 }] */
    /* JADX WARN: Removed duplicated region for block: B:89:0x02c1  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x02d7  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$loadExceptions$1$NoticeAndSoundSettingActivity() {
        /*
            Method dump skipped, instruction units count: 918
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.settings.NoticeAndSoundSettingActivity.lambda$loadExceptions$1$NoticeAndSoundSettingActivity():void");
    }

    public /* synthetic */ void lambda$null$0$NoticeAndSoundSettingActivity(ArrayList users, ArrayList chats, ArrayList encryptedChats, ArrayList usersResult, ArrayList chatsResult, ArrayList channelsResult) {
        MessagesController.getInstance(this.currentAccount).putUsers(users, true);
        MessagesController.getInstance(this.currentAccount).putChats(chats, true);
        MessagesController.getInstance(this.currentAccount).putEncryptedChats(encryptedChats, true);
        this.exceptionUsers = usersResult;
        this.exceptionChats = chatsResult;
        this.exceptionChannels = channelsResult;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setTitle(LocaleController.getString("Notifications", R.string.Notifications));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_setting_notice, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initView(context);
        initGlobalSetting();
        initListener();
        return this.fragmentView;
    }

    private void initView(Context context) {
        this.fragmentView.findViewById(R.attr.rl_show_notice).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0, 0, Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_preview_message).setBackground(Theme.getSelectorDrawable(true));
        this.fragmentView.findViewById(R.attr.rl_sound).setBackground(Theme.getRoundRectSelectorDrawable(0, 0, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_group_show_notice).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0, 0, Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_group_preview_message).setBackground(Theme.getSelectorDrawable(true));
        this.fragmentView.findViewById(R.attr.rl_group_sound).setBackground(Theme.getRoundRectSelectorDrawable(0, 0, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_channel_show_notice).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0, 0, Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_channel_preview_message).setBackground(Theme.getSelectorDrawable(true));
        this.fragmentView.findViewById(R.attr.rl_channel_sound).setBackground(Theme.getRoundRectSelectorDrawable(0, 0, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_app_show_notice).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0, 0, Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_app_shake_notice).setBackground(Theme.getSelectorDrawable(true));
        this.fragmentView.findViewById(R.attr.rl_app_preview_notice).setBackground(Theme.getRoundRectSelectorDrawable(0, 0, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_include_closed_dialog).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0, 0, Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_msg_count_statistics).setBackground(Theme.getRoundRectSelectorDrawable(0, 0, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_new_contacter_add).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_reset).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
    }

    private void initListener() {
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.settings.NoticeAndSoundSettingActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    NoticeAndSoundSettingActivity.this.finishFragment();
                }
            }
        });
        this.fragmentView.findViewById(R.attr.rl_show_notice).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$h0nhEoL5lZsbKkZamQpzoF7kTXI
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$3$NoticeAndSoundSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_preview_message).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$lGIZM09RlcnAqPXC-6TR4PIR8rk
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$4$NoticeAndSoundSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_sound).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$r218GrKYkHQdalzOeAwpCbofgOc
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$5$NoticeAndSoundSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_group_show_notice).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$v74DiEUS8x2mC3Jj-3SlUxFGM_8
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$7$NoticeAndSoundSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_group_preview_message).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$7qFcMJ-GWHXjYmtyjKA5nEGMLns
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$8$NoticeAndSoundSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_group_sound).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$NzlIQPgiHaBQxeHtRac9VBVo47M
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$9$NoticeAndSoundSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_channel_show_notice).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$DfuFU7RG0llAUSr6YVaF4xNLQP8
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$11$NoticeAndSoundSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_channel_preview_message).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$8PuGO8ZyQe9MfgUPpu6axmiy6Kg
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$12$NoticeAndSoundSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_channel_sound).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$m1GD5iHc3g-fapA0vyp9v2M0F_U
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$13$NoticeAndSoundSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_app_show_notice).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$XRfCq16aXr7f-lMboAjvyWbnCjg
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$14$NoticeAndSoundSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_app_shake_notice).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$wnLD9dspC3Te3a34Lgw7Y_arRKs
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$15$NoticeAndSoundSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_app_preview_notice).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$Vj9UdCh4Z9j4BO6A0TherEiB9qA
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$16$NoticeAndSoundSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_include_closed_dialog).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$d1TZlBbaHupP6NgPjXGy5PG_-lU
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$17$NoticeAndSoundSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_msg_count_statistics).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$cwO3nwAwKG__QJWKDGH1LgsS2K8
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$18$NoticeAndSoundSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_new_contacter_add).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$A2KAx_QRCemc-72mDKhJtRRVKTI
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$20$NoticeAndSoundSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_reset).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$_HLv48JrsElM8vYh0wqNEofygnk
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$24$NoticeAndSoundSettingActivity(view);
            }
        });
    }

    public /* synthetic */ void lambda$initListener$3$NoticeAndSoundSettingActivity(View view) {
        boolean enabled = getNotificationsController().isGlobalNotificationsEnabled(1);
        if (!enabled) {
            getNotificationsController().setGlobalNotificationsEnabled(1, 0);
            ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_show)).setChecked(!enabled, true);
            setPrivateSettingEnabled(((MrySwitch) this.fragmentView.findViewById(R.attr.switch_show)).isChecked());
            return;
        }
        AlertsCreator.showCustomNotificationsDialog(this, 0L, 1, this.exceptionUsers, this.currentAccount, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$qfuqu_HO71iJKT9y-NUnWfQexWY
            @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
            public final void run(int i) {
                this.f$0.lambda$null$2$NoticeAndSoundSettingActivity(i);
            }
        });
    }

    public /* synthetic */ void lambda$null$2$NoticeAndSoundSettingActivity(int param) {
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_show)).setChecked(getNotificationsController().isGlobalNotificationsEnabled(1), true);
        setPrivateSettingEnabled(((MrySwitch) this.fragmentView.findViewById(R.attr.switch_show)).isChecked());
    }

    public /* synthetic */ void lambda$initListener$4$NoticeAndSoundSettingActivity(View view) {
        if (!view.isEnabled()) {
            return;
        }
        SharedPreferences preferences = getNotificationsSettings();
        SharedPreferences.Editor editor = preferences.edit();
        boolean enabled = preferences.getBoolean("EnablePreviewAll", true);
        editor.putBoolean("EnablePreviewAll", !enabled);
        editor.commit();
        getNotificationsController().updateServerNotificationsSettings(1);
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_preview_message)).setChecked(!enabled, true);
    }

    public /* synthetic */ void lambda$initListener$5$NoticeAndSoundSettingActivity(View view) {
        if (!view.isEnabled()) {
            return;
        }
        try {
            SharedPreferences preferences = getNotificationsSettings();
            Intent tmpIntent = new Intent("android.intent.action.RINGTONE_PICKER");
            tmpIntent.putExtra("android.intent.extra.ringtone.TYPE", 2);
            tmpIntent.putExtra("android.intent.extra.ringtone.SHOW_DEFAULT", true);
            tmpIntent.putExtra("android.intent.extra.ringtone.SHOW_SILENT", true);
            tmpIntent.putExtra("android.intent.extra.ringtone.DEFAULT_URI", RingtoneManager.getDefaultUri(2));
            Parcelable currentSound = null;
            String defaultPath = null;
            Uri defaultUri = Settings.System.DEFAULT_NOTIFICATION_URI;
            if (defaultUri != null) {
                defaultPath = defaultUri.getPath();
            }
            String path = preferences.getString("GlobalSoundPath", defaultPath);
            if (path != null && !path.equals("NoSound")) {
                currentSound = path.equals(defaultPath) ? defaultUri : Uri.parse(path);
            }
            tmpIntent.putExtra("android.intent.extra.ringtone.EXISTING_URI", currentSound);
            startActivityForResult(tmpIntent, 1);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$initListener$7$NoticeAndSoundSettingActivity(View view) {
        boolean enabled = getNotificationsController().isGlobalNotificationsEnabled(0);
        if (!enabled) {
            getNotificationsController().setGlobalNotificationsEnabled(0, 0);
            ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_group_show)).setChecked(!enabled, true);
            setGroupSettingEnabled(((MrySwitch) this.fragmentView.findViewById(R.attr.switch_group_show)).isChecked());
            return;
        }
        AlertsCreator.showCustomNotificationsDialog(this, 0L, 0, this.exceptionChats, this.currentAccount, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$iaJ_HYfxwYHeQ8QIWYQMjUBeYV8
            @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
            public final void run(int i) {
                this.f$0.lambda$null$6$NoticeAndSoundSettingActivity(i);
            }
        });
    }

    public /* synthetic */ void lambda$null$6$NoticeAndSoundSettingActivity(int param) {
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_group_show)).setChecked(getNotificationsController().isGlobalNotificationsEnabled(0), true);
        setGroupSettingEnabled(((MrySwitch) this.fragmentView.findViewById(R.attr.switch_group_show)).isChecked());
    }

    public /* synthetic */ void lambda$initListener$8$NoticeAndSoundSettingActivity(View view) {
        if (!view.isEnabled()) {
            return;
        }
        SharedPreferences preferences = getNotificationsSettings();
        SharedPreferences.Editor editor = preferences.edit();
        boolean enabled = preferences.getBoolean("EnablePreviewGroup", true);
        editor.putBoolean("EnablePreviewGroup", !enabled);
        editor.commit();
        getNotificationsController().updateServerNotificationsSettings(0);
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_group_preview_message)).setChecked(!enabled, true);
    }

    public /* synthetic */ void lambda$initListener$9$NoticeAndSoundSettingActivity(View view) {
        if (!view.isEnabled()) {
            return;
        }
        try {
            SharedPreferences preferences = getNotificationsSettings();
            Intent tmpIntent = new Intent("android.intent.action.RINGTONE_PICKER");
            tmpIntent.putExtra("android.intent.extra.ringtone.TYPE", 2);
            tmpIntent.putExtra("android.intent.extra.ringtone.SHOW_DEFAULT", true);
            tmpIntent.putExtra("android.intent.extra.ringtone.SHOW_SILENT", true);
            tmpIntent.putExtra("android.intent.extra.ringtone.DEFAULT_URI", RingtoneManager.getDefaultUri(2));
            Parcelable currentSound = null;
            String defaultPath = null;
            Uri defaultUri = Settings.System.DEFAULT_NOTIFICATION_URI;
            if (defaultUri != null) {
                defaultPath = defaultUri.getPath();
            }
            String path = preferences.getString("GroupSoundPath", defaultPath);
            if (path != null && !path.equals("NoSound")) {
                currentSound = path.equals(defaultPath) ? defaultUri : Uri.parse(path);
            }
            tmpIntent.putExtra("android.intent.extra.ringtone.EXISTING_URI", currentSound);
            startActivityForResult(tmpIntent, 0);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$initListener$11$NoticeAndSoundSettingActivity(View view) {
        boolean enabled = getNotificationsController().isGlobalNotificationsEnabled(2);
        if (!enabled) {
            getNotificationsController().setGlobalNotificationsEnabled(2, 0);
            ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_channel_show)).setChecked(!enabled, true);
            setChannelSettingEnabled(((MrySwitch) this.fragmentView.findViewById(R.attr.switch_channel_show)).isChecked());
            return;
        }
        AlertsCreator.showCustomNotificationsDialog(this, 0L, 2, this.exceptionChannels, this.currentAccount, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$UsYmFde6QoaLz3SQeEqWBaHFqh0
            @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
            public final void run(int i) {
                this.f$0.lambda$null$10$NoticeAndSoundSettingActivity(i);
            }
        });
    }

    public /* synthetic */ void lambda$null$10$NoticeAndSoundSettingActivity(int param) {
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_channel_show)).setChecked(getNotificationsController().isGlobalNotificationsEnabled(2), true);
        setChannelSettingEnabled(((MrySwitch) this.fragmentView.findViewById(R.attr.switch_channel_show)).isChecked());
    }

    public /* synthetic */ void lambda$initListener$12$NoticeAndSoundSettingActivity(View view) {
        if (!view.isEnabled()) {
            return;
        }
        SharedPreferences preferences = getNotificationsSettings();
        SharedPreferences.Editor editor = preferences.edit();
        boolean enabled = preferences.getBoolean("EnablePreviewChannel", true);
        editor.putBoolean("EnablePreviewChannel", !enabled);
        editor.commit();
        getNotificationsController().updateServerNotificationsSettings(2);
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_channel_preview_message)).setChecked(!enabled, true);
    }

    public /* synthetic */ void lambda$initListener$13$NoticeAndSoundSettingActivity(View view) {
        if (!view.isEnabled()) {
            return;
        }
        try {
            SharedPreferences preferences = getNotificationsSettings();
            Intent tmpIntent = new Intent("android.intent.action.RINGTONE_PICKER");
            tmpIntent.putExtra("android.intent.extra.ringtone.TYPE", 2);
            tmpIntent.putExtra("android.intent.extra.ringtone.SHOW_DEFAULT", true);
            tmpIntent.putExtra("android.intent.extra.ringtone.SHOW_SILENT", true);
            tmpIntent.putExtra("android.intent.extra.ringtone.DEFAULT_URI", RingtoneManager.getDefaultUri(2));
            Parcelable currentSound = null;
            String defaultPath = null;
            Uri defaultUri = Settings.System.DEFAULT_NOTIFICATION_URI;
            if (defaultUri != null) {
                defaultPath = defaultUri.getPath();
            }
            String path = preferences.getString("ChannelSoundPath", defaultPath);
            if (path != null && !path.equals("NoSound")) {
                currentSound = path.equals(defaultPath) ? defaultUri : Uri.parse(path);
            }
            tmpIntent.putExtra("android.intent.extra.ringtone.EXISTING_URI", currentSound);
            startActivityForResult(tmpIntent, 2);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$initListener$14$NoticeAndSoundSettingActivity(View view) {
        SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
        SharedPreferences.Editor editor = preferences.edit();
        boolean enabled = preferences.getBoolean("EnableInAppSounds", true);
        editor.putBoolean("EnableInAppSounds", !enabled);
        editor.commit();
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_app_show)).setChecked(!enabled, true);
    }

    public /* synthetic */ void lambda$initListener$15$NoticeAndSoundSettingActivity(View view) {
        SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
        SharedPreferences.Editor editor = preferences.edit();
        boolean enabled = preferences.getBoolean("EnableInAppVibrate", true);
        editor.putBoolean("EnableInAppVibrate", !enabled);
        editor.commit();
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_app_shake)).setChecked(!enabled, true);
    }

    public /* synthetic */ void lambda$initListener$16$NoticeAndSoundSettingActivity(View view) {
        SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
        SharedPreferences.Editor editor = preferences.edit();
        boolean enabled = preferences.getBoolean("EnableInAppPreview", true);
        editor.putBoolean("EnableInAppPreview", !enabled);
        editor.commit();
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_app_preview_notice)).setChecked(!enabled, true);
    }

    public /* synthetic */ void lambda$initListener$17$NoticeAndSoundSettingActivity(View view) {
        SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
        SharedPreferences.Editor editor = preferences.edit();
        boolean enabled = NotificationsController.getInstance(this.currentAccount).showBadgeMuted;
        NotificationsController.getInstance(this.currentAccount).showBadgeMuted = !enabled;
        editor.putBoolean("badgeNumberMuted", NotificationsController.getInstance(this.currentAccount).showBadgeMuted);
        editor.commit();
        NotificationsController.getInstance(this.currentAccount).updateBadge();
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_include_closed_dialog)).setChecked(!enabled, true);
    }

    public /* synthetic */ void lambda$initListener$18$NoticeAndSoundSettingActivity(View view) {
        SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
        SharedPreferences.Editor editor = preferences.edit();
        boolean enabled = NotificationsController.getInstance(this.currentAccount).showBadgeMessages;
        NotificationsController.getInstance(this.currentAccount).showBadgeMessages = !enabled;
        editor.putBoolean("badgeNumberMessages", NotificationsController.getInstance(this.currentAccount).showBadgeMessages);
        editor.commit();
        NotificationsController.getInstance(this.currentAccount).updateBadge();
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_msg_count_statistics)).setChecked(!enabled, true);
    }

    public /* synthetic */ void lambda$initListener$20$NoticeAndSoundSettingActivity(View view) {
        SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
        SharedPreferences.Editor editor = preferences.edit();
        boolean enabled = preferences.getBoolean("EnableContactJoined", true);
        MessagesController.getInstance(this.currentAccount).enableJoined = !enabled;
        editor.putBoolean("EnableContactJoined", !enabled);
        editor.commit();
        TLRPC.TL_account_setContactSignUpNotification req = new TLRPC.TL_account_setContactSignUpNotification();
        req.silent = enabled;
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$ZgNx5-m35UViAlgtcVjrwnHGYJo
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                NoticeAndSoundSettingActivity.lambda$null$19(tLObject, tL_error);
            }
        });
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_new_contacter_add)).setChecked(!enabled, true);
    }

    static /* synthetic */ void lambda$null$19(TLObject response, TLRPC.TL_error error) {
    }

    public /* synthetic */ void lambda$initListener$24$NoticeAndSoundSettingActivity(View view) {
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setMessage(LocaleController.getString("ResetNotificationsAlert", R.string.ResetNotificationsAlert));
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setPositiveButton(LocaleController.getString("Reset", R.string.Reset), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$bU0ILRLCgaX-YPMUO4I4tyx7GU0
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$23$NoticeAndSoundSettingActivity(dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$null$23$NoticeAndSoundSettingActivity(DialogInterface dialogInterface, int i) {
        if (this.reseting) {
            return;
        }
        this.reseting = true;
        TLRPC.TL_account_resetNotifySettings req = new TLRPC.TL_account_resetNotifySettings();
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$3a-K-86_QnsKQ6z1kIj75lob150
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$22$NoticeAndSoundSettingActivity(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$null$22$NoticeAndSoundSettingActivity(TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$NoticeAndSoundSettingActivity$skbS2Oa8cR3RiiQjWczXXxykHGc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$21$NoticeAndSoundSettingActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$21$NoticeAndSoundSettingActivity() {
        MessagesController.getInstance(this.currentAccount).enableJoined = true;
        this.reseting = false;
        SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
        SharedPreferences.Editor editor = preferences.edit();
        editor.clear();
        editor.commit();
        this.exceptionChats.clear();
        this.exceptionUsers.clear();
        initGlobalSetting();
        if (getParentActivity() != null) {
            ToastUtils.show(R.string.ResetNotificationsText);
        }
    }

    private void initGlobalSetting() {
        StringBuilder builder = new StringBuilder();
        SharedPreferences preferences = getNotificationsSettings();
        int offUntil = preferences.getInt("EnableAll2", 0);
        int currentTime = getConnectionsManager().getCurrentTime();
        boolean z = offUntil < currentTime;
        boolean enabled = z;
        if (z) {
            builder.append(LocaleController.getString("NotificationsOn", R.string.NotificationsOn));
        } else if (offUntil - 31536000 >= currentTime) {
            builder.append(LocaleController.getString("NotificationsOff", R.string.NotificationsOff));
        } else {
            builder.append(LocaleController.formatString("NotificationsOffUntil", R.string.NotificationsOffUntil, LocaleController.stringForMessageListDate(offUntil)));
        }
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_show)).setChecked(enabled, true);
        setPrivateSettingEnabled(enabled);
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_preview_message)).setChecked(preferences.getBoolean("EnablePreviewAll", true), true);
        String value = preferences.getString("GlobalSound", LocaleController.getString("SoundDefault", R.string.SoundDefault));
        if (value.equals("NoSound")) {
            value = LocaleController.getString("NoSound", R.string.NoSound);
        }
        ((TextView) this.fragmentView.findViewById(R.attr.tv_sound_type)).setText(value);
        initGroupSetting();
        initChannelSetting();
        initOtherSetting();
    }

    private void initGroupSetting() {
        StringBuilder builder = new StringBuilder();
        SharedPreferences preferences = getNotificationsSettings();
        int offUntil = preferences.getInt("EnableGroup2", 0);
        int currentTime = getConnectionsManager().getCurrentTime();
        boolean z = offUntil < currentTime;
        boolean enabled = z;
        if (z) {
            builder.append(LocaleController.getString("NotificationsOn", R.string.NotificationsOn));
        } else if (offUntil - 31536000 >= currentTime) {
            builder.append(LocaleController.getString("NotificationsOff", R.string.NotificationsOff));
        } else {
            builder.append(LocaleController.formatString("NotificationsOffUntil", R.string.NotificationsOffUntil, LocaleController.stringForMessageListDate(offUntil)));
        }
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_group_show)).setChecked(enabled, true);
        setGroupSettingEnabled(enabled);
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_group_preview_message)).setChecked(preferences.getBoolean("EnablePreviewGroup", true), true);
        String value = preferences.getString("GroupSound", LocaleController.getString("SoundDefault", R.string.SoundDefault));
        if (value.equals("NoSound")) {
            value = LocaleController.getString("NoSound", R.string.NoSound);
        }
        ((TextView) this.fragmentView.findViewById(R.attr.tv_group_sound_type)).setText(value);
    }

    private void initChannelSetting() {
        StringBuilder builder = new StringBuilder();
        SharedPreferences preferences = getNotificationsSettings();
        int offUntil = preferences.getInt("EnableChannel2", 0);
        int currentTime = getConnectionsManager().getCurrentTime();
        boolean z = offUntil < currentTime;
        boolean enabled = z;
        if (z) {
            builder.append(LocaleController.getString("NotificationsOn", R.string.NotificationsOn));
        } else if (offUntil - 31536000 >= currentTime) {
            builder.append(LocaleController.getString("NotificationsOff", R.string.NotificationsOff));
        } else {
            builder.append(LocaleController.formatString("NotificationsOffUntil", R.string.NotificationsOffUntil, LocaleController.stringForMessageListDate(offUntil)));
        }
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_channel_show)).setChecked(enabled, true);
        setChannelSettingEnabled(enabled);
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_channel_preview_message)).setChecked(preferences.getBoolean("EnablePreviewChannel", true), true);
        String value = preferences.getString("ChannelSound", LocaleController.getString("SoundDefault", R.string.SoundDefault));
        if (value.equals("NoSound")) {
            value = LocaleController.getString("NoSound", R.string.NoSound);
        }
        ((TextView) this.fragmentView.findViewById(R.attr.tv_channel_sound_type)).setText(value);
    }

    private void initOtherSetting() {
        SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_app_show)).setChecked(preferences.getBoolean("EnableInAppSounds", true), true);
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_app_shake)).setChecked(preferences.getBoolean("EnableInAppVibrate", true), true);
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_app_preview_notice)).setChecked(preferences.getBoolean("EnableInAppPreview", true), true);
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_include_closed_dialog)).setChecked(NotificationsController.getInstance(this.currentAccount).showBadgeMuted, true);
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_msg_count_statistics)).setChecked(NotificationsController.getInstance(this.currentAccount).showBadgeMessages, true);
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_new_contacter_add)).setChecked(preferences.getBoolean("EnableContactJoined", true), true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
        Ringtone rng;
        if (resultCode == -1) {
            Uri ringtone = (Uri) data.getParcelableExtra("android.intent.extra.ringtone.PICKED_URI");
            String name = null;
            if (ringtone != null && (rng = RingtoneManager.getRingtone(getParentActivity(), ringtone)) != null) {
                if (ringtone.equals(Settings.System.DEFAULT_NOTIFICATION_URI)) {
                    name = LocaleController.getString("SoundDefault", R.string.SoundDefault);
                } else {
                    name = rng.getTitle(getParentActivity());
                }
                rng.stop();
            }
            SharedPreferences preferences = getNotificationsSettings();
            SharedPreferences.Editor editor = preferences.edit();
            if (requestCode == 1) {
                if (name != null && ringtone != null) {
                    editor.putString("GlobalSound", name);
                    editor.putString("GlobalSoundPath", ringtone.toString());
                } else {
                    editor.putString("GlobalSound", "NoSound");
                    editor.putString("GlobalSoundPath", "NoSound");
                }
                ((TextView) this.fragmentView.findViewById(R.attr.tv_sound_type)).setText(name == null ? LocaleController.getString("NoSound", R.string.NoSound) : name);
            } else if (requestCode == 0) {
                if (name != null && ringtone != null) {
                    editor.putString("GroupSound", name);
                    editor.putString("GroupSoundPath", ringtone.toString());
                } else {
                    editor.putString("GroupSound", "NoSound");
                    editor.putString("GroupSoundPath", "NoSound");
                }
                ((TextView) this.fragmentView.findViewById(R.attr.tv_group_sound_type)).setText(name == null ? LocaleController.getString("NoSound", R.string.NoSound) : name);
            } else if (requestCode == 2) {
                if (name != null && ringtone != null) {
                    editor.putString("ChannelSound", name);
                    editor.putString("ChannelSoundPath", ringtone.toString());
                } else {
                    editor.putString("ChannelSound", "NoSound");
                    editor.putString("ChannelSoundPath", "NoSound");
                }
                ((TextView) this.fragmentView.findViewById(R.attr.tv_channel_sound_type)).setText(name == null ? LocaleController.getString("NoSound", R.string.NoSound) : name);
            }
            editor.commit();
            getNotificationsController().updateServerNotificationsSettings(requestCode);
        }
    }

    private void setGroupSettingEnabled(boolean blnEnable) {
        this.fragmentView.findViewById(R.attr.tv_group_preview_message).setAlpha(blnEnable ? 1.0f : 0.5f);
        this.fragmentView.findViewById(R.attr.switch_group_preview_message).setAlpha(blnEnable ? 1.0f : 0.5f);
        this.fragmentView.findViewById(R.attr.tv_group_sound).setAlpha(blnEnable ? 1.0f : 0.5f);
        this.fragmentView.findViewById(R.attr.tv_group_sound_type).setAlpha(blnEnable ? 1.0f : 0.5f);
        this.fragmentView.findViewById(R.attr.rl_group_sound).setEnabled(blnEnable);
        this.fragmentView.findViewById(R.attr.rl_group_preview_message).setEnabled(blnEnable);
    }

    private void setChannelSettingEnabled(boolean blnEnable) {
        this.fragmentView.findViewById(R.attr.tv_channel_preview_message).setAlpha(blnEnable ? 1.0f : 0.5f);
        this.fragmentView.findViewById(R.attr.switch_channel_preview_message).setAlpha(blnEnable ? 1.0f : 0.5f);
        this.fragmentView.findViewById(R.attr.tv_channel_sound).setAlpha(blnEnable ? 1.0f : 0.5f);
        this.fragmentView.findViewById(R.attr.tv_channel_sound_type).setAlpha(blnEnable ? 1.0f : 0.5f);
        this.fragmentView.findViewById(R.attr.rl_channel_sound).setEnabled(blnEnable);
        this.fragmentView.findViewById(R.attr.rl_channel_preview_message).setEnabled(blnEnable);
    }

    private void setPrivateSettingEnabled(boolean blnEnable) {
        this.fragmentView.findViewById(R.attr.tv_private_preview_message).setAlpha(blnEnable ? 1.0f : 0.5f);
        this.fragmentView.findViewById(R.attr.switch_preview_message).setAlpha(blnEnable ? 1.0f : 0.5f);
        this.fragmentView.findViewById(R.attr.tv_private_sound).setAlpha(blnEnable ? 1.0f : 0.5f);
        this.fragmentView.findViewById(R.attr.tv_sound_type).setAlpha(blnEnable ? 1.0f : 0.5f);
        this.fragmentView.findViewById(R.attr.rl_sound).setEnabled(blnEnable);
        this.fragmentView.findViewById(R.attr.rl_preview_message).setEnabled(blnEnable);
    }

    private void setColors() {
        this.fragmentView.findViewById(R.attr.rl_show_notice).setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
    }
}
