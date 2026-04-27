package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.media.Ringtone;
import android.media.RingtoneManager;
import android.net.Uri;
import android.os.Build;
import android.os.Parcelable;
import android.provider.Settings;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.exoplayer2.extractor.ts.PsExtractor;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.NotificationsController;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.NotificationsCheckCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextCheckCell;
import im.uwrkaxlmjj.ui.cells.TextDetailSettingsCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class NotificationsSettingsActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private int accountsAllRow;
    private int accountsInfoRow;
    private int accountsSectionRow;
    private ListAdapter adapter;
    private int androidAutoAlertRow;
    private int badgeNumberMessagesRow;
    private int badgeNumberMutedRow;
    private int badgeNumberSection;
    private int badgeNumberSection2Row;
    private int badgeNumberShowRow;
    private int callsRingtoneRow;
    private int callsSection2Row;
    private int callsSectionRow;
    private int callsVibrateRow;
    private int channelsRow;
    private int contactJoinedRow;
    private int eventsSection2Row;
    private int eventsSectionRow;
    private int groupRow;
    private int inappPreviewRow;
    private int inappPriorityRow;
    private int inappSectionRow;
    private int inappSoundRow;
    private int inappVibrateRow;
    private int inchatSoundRow;
    private LinearLayoutManager layoutManager;
    private RecyclerListView listView;
    private int notificationsSection2Row;
    private int notificationsSectionRow;
    private int notificationsServiceConnectionRow;
    private int notificationsServiceRow;
    private int otherSection2Row;
    private int otherSectionRow;
    private int pinnedMessageRow;
    private int privateRow;
    private int repeatRow;
    private int resetNotificationsRow;
    private int resetSection2Row;
    private int resetSectionRow;
    private boolean reseting = false;
    private ArrayList<NotificationException> exceptionUsers = null;
    private ArrayList<NotificationException> exceptionChats = null;
    private ArrayList<NotificationException> exceptionChannels = null;
    private int rowCount = 0;

    public static class NotificationException {
        public long did;
        public boolean hasCustom;
        public int muteUntil;
        public int notify;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        MessagesController.getInstance(this.currentAccount).loadSignUpNotificationsSettings();
        loadExceptions();
        if (UserConfig.getActivatedAccountsCount() > 1) {
            int i = this.rowCount;
            int i2 = i + 1;
            this.rowCount = i2;
            this.accountsSectionRow = i;
            int i3 = i2 + 1;
            this.rowCount = i3;
            this.accountsAllRow = i2;
            this.rowCount = i3 + 1;
            this.accountsInfoRow = i3;
        } else {
            this.accountsSectionRow = -1;
            this.accountsAllRow = -1;
            this.accountsInfoRow = -1;
        }
        int i4 = this.rowCount;
        int i5 = i4 + 1;
        this.rowCount = i5;
        this.notificationsSectionRow = i4;
        int i6 = i5 + 1;
        this.rowCount = i6;
        this.privateRow = i5;
        int i7 = i6 + 1;
        this.rowCount = i7;
        this.groupRow = i6;
        int i8 = i7 + 1;
        this.rowCount = i8;
        this.channelsRow = i7;
        int i9 = i8 + 1;
        this.rowCount = i9;
        this.notificationsSection2Row = i8;
        int i10 = i9 + 1;
        this.rowCount = i10;
        this.callsSectionRow = i9;
        int i11 = i10 + 1;
        this.rowCount = i11;
        this.callsVibrateRow = i10;
        int i12 = i11 + 1;
        this.rowCount = i12;
        this.callsRingtoneRow = i11;
        int i13 = i12 + 1;
        this.rowCount = i13;
        this.eventsSection2Row = i12;
        int i14 = i13 + 1;
        this.rowCount = i14;
        this.badgeNumberSection = i13;
        int i15 = i14 + 1;
        this.rowCount = i15;
        this.badgeNumberShowRow = i14;
        int i16 = i15 + 1;
        this.rowCount = i16;
        this.badgeNumberMutedRow = i15;
        int i17 = i16 + 1;
        this.rowCount = i17;
        this.badgeNumberMessagesRow = i16;
        int i18 = i17 + 1;
        this.rowCount = i18;
        this.badgeNumberSection2Row = i17;
        int i19 = i18 + 1;
        this.rowCount = i19;
        this.inappSectionRow = i18;
        int i20 = i19 + 1;
        this.rowCount = i20;
        this.inappSoundRow = i19;
        int i21 = i20 + 1;
        this.rowCount = i21;
        this.inappVibrateRow = i20;
        int i22 = i21 + 1;
        this.rowCount = i22;
        this.inappPreviewRow = i21;
        this.rowCount = i22 + 1;
        this.inchatSoundRow = i22;
        if (Build.VERSION.SDK_INT >= 21) {
            int i23 = this.rowCount;
            this.rowCount = i23 + 1;
            this.inappPriorityRow = i23;
        } else {
            this.inappPriorityRow = -1;
        }
        int i24 = this.rowCount;
        int i25 = i24 + 1;
        this.rowCount = i25;
        this.callsSection2Row = i24;
        int i26 = i25 + 1;
        this.rowCount = i26;
        this.eventsSectionRow = i25;
        int i27 = i26 + 1;
        this.rowCount = i27;
        this.contactJoinedRow = i26;
        int i28 = i27 + 1;
        this.rowCount = i28;
        this.pinnedMessageRow = i27;
        int i29 = i28 + 1;
        this.rowCount = i29;
        this.otherSection2Row = i28;
        int i30 = i29 + 1;
        this.rowCount = i30;
        this.otherSectionRow = i29;
        int i31 = i30 + 1;
        this.rowCount = i31;
        this.notificationsServiceRow = i30;
        int i32 = i31 + 1;
        this.rowCount = i32;
        this.notificationsServiceConnectionRow = i31;
        this.androidAutoAlertRow = -1;
        int i33 = i32 + 1;
        this.rowCount = i33;
        this.repeatRow = i32;
        int i34 = i33 + 1;
        this.rowCount = i34;
        this.resetSection2Row = i33;
        int i35 = i34 + 1;
        this.rowCount = i35;
        this.resetSectionRow = i34;
        this.rowCount = i35 + 1;
        this.resetNotificationsRow = i35;
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.notificationsSettingsUpdated);
        return super.onFragmentCreate();
    }

    private void loadExceptions() {
        MessagesStorage.getInstance(this.currentAccount).getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsSettingsActivity$4dNL514LOPGEa9o5NIPlSOKqkSs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadExceptions$1$NotificationsSettingsActivity();
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
    public /* synthetic */ void lambda$loadExceptions$1$NotificationsSettingsActivity() {
        /*
            Method dump skipped, instruction units count: 918
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.NotificationsSettingsActivity.lambda$loadExceptions$1$NotificationsSettingsActivity():void");
    }

    public /* synthetic */ void lambda$null$0$NotificationsSettingsActivity(ArrayList users, ArrayList chats, ArrayList encryptedChats, ArrayList usersResult, ArrayList chatsResult, ArrayList channelsResult) {
        MessagesController.getInstance(this.currentAccount).putUsers(users, true);
        MessagesController.getInstance(this.currentAccount).putChats(chats, true);
        MessagesController.getInstance(this.currentAccount).putEncryptedChats(encryptedChats, true);
        this.exceptionUsers = usersResult;
        this.exceptionChats = chatsResult;
        this.exceptionChannels = channelsResult;
        this.adapter.notifyItemChanged(this.privateRow);
        this.adapter.notifyItemChanged(this.groupRow);
        this.adapter.notifyItemChanged(this.channelsRow);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.notificationsSettingsUpdated);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("NotificationsAndSounds", R.string.NotificationsAndSounds));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.NotificationsSettingsActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    NotificationsSettingsActivity.this.finishFragment();
                }
            }
        });
        this.fragmentView = new FrameLayout(context);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setItemAnimator(null);
        this.listView.setLayoutAnimation(null);
        RecyclerListView recyclerListView2 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false) { // from class: im.uwrkaxlmjj.ui.NotificationsSettingsActivity.2
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        this.layoutManager = linearLayoutManager;
        recyclerListView2.setLayoutManager(linearLayoutManager);
        this.listView.setVerticalScrollBarEnabled(false);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1.0f));
        RecyclerListView recyclerListView3 = this.listView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.adapter = listAdapter;
        recyclerListView3.setAdapter(listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListenerExtended() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsSettingsActivity$oZiaNO7Uka_Y4zCLL6lPM06e3B0
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListenerExtended
            public final void onItemClick(View view, int i, float f, float f2) {
                this.f$0.lambda$createView$8$NotificationsSettingsActivity(view, i, f, f2);
            }
        });
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$8$NotificationsSettingsActivity(View view, final int position, float x, float y) {
        int type;
        ArrayList<NotificationException> exceptions;
        boolean enabled = false;
        if (getParentActivity() == null) {
            return;
        }
        if (position == this.privateRow || position == this.groupRow || position == this.channelsRow) {
            if (position == this.privateRow) {
                type = 1;
                exceptions = this.exceptionUsers;
            } else {
                int type2 = this.groupRow;
                if (position == type2) {
                    type = 0;
                    exceptions = this.exceptionChats;
                } else {
                    type = 2;
                    exceptions = this.exceptionChannels;
                }
            }
            if (exceptions == null) {
                return;
            }
            NotificationsCheckCell checkCell = (NotificationsCheckCell) view;
            enabled = NotificationsController.getInstance(this.currentAccount).isGlobalNotificationsEnabled(type);
            if ((LocaleController.isRTL && x <= AndroidUtilities.dp(76.0f)) || (!LocaleController.isRTL && x >= view.getMeasuredWidth() - AndroidUtilities.dp(76.0f))) {
                NotificationsController.getInstance(this.currentAccount).setGlobalNotificationsEnabled(type, !enabled ? 0 : Integer.MAX_VALUE);
                showExceptionsAlert(position);
                checkCell.setChecked(!enabled, 0);
                this.adapter.notifyItemChanged(position);
            } else {
                presentFragment(new NotificationsCustomSettingsActivity(type, exceptions));
            }
        } else if (position == this.callsRingtoneRow) {
            try {
                SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
                Intent tmpIntent = new Intent("android.intent.action.RINGTONE_PICKER");
                tmpIntent.putExtra("android.intent.extra.ringtone.TYPE", 1);
                tmpIntent.putExtra("android.intent.extra.ringtone.SHOW_DEFAULT", true);
                tmpIntent.putExtra("android.intent.extra.ringtone.SHOW_SILENT", true);
                tmpIntent.putExtra("android.intent.extra.ringtone.DEFAULT_URI", RingtoneManager.getDefaultUri(1));
                Parcelable currentSound = null;
                String defaultPath = null;
                Uri defaultUri = Settings.System.DEFAULT_RINGTONE_URI;
                if (defaultUri != null) {
                    defaultPath = defaultUri.getPath();
                }
                String path = preferences.getString("CallsRingtonePath", defaultPath);
                if (path != null && !path.equals("NoSound")) {
                    currentSound = path.equals(defaultPath) ? defaultUri : Uri.parse(path);
                }
                tmpIntent.putExtra("android.intent.extra.ringtone.EXISTING_URI", currentSound);
                startActivityForResult(tmpIntent, position);
            } catch (Exception e) {
                FileLog.e(e);
            }
        } else if (position != this.resetNotificationsRow) {
            if (position != this.inappSoundRow) {
                if (position != this.inappVibrateRow) {
                    if (position != this.inappPreviewRow) {
                        if (position != this.inchatSoundRow) {
                            if (position != this.inappPriorityRow) {
                                if (position != this.contactJoinedRow) {
                                    if (position != this.pinnedMessageRow) {
                                        if (position != this.androidAutoAlertRow) {
                                            if (position != this.badgeNumberShowRow) {
                                                if (position != this.badgeNumberMutedRow) {
                                                    if (position != this.badgeNumberMessagesRow) {
                                                        if (position != this.notificationsServiceConnectionRow) {
                                                            if (position != this.accountsAllRow) {
                                                                if (position != this.notificationsServiceRow) {
                                                                    if (position == this.callsVibrateRow) {
                                                                        if (getParentActivity() == null) {
                                                                            return;
                                                                        }
                                                                        String key = null;
                                                                        if (position == this.callsVibrateRow) {
                                                                            key = "vibrate_calls";
                                                                        }
                                                                        showDialog(AlertsCreator.createVibrationSelectDialog(getParentActivity(), 0L, key, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsSettingsActivity$zpZoLS_vM3FsoebJGfX7VuSq-PU
                                                                            @Override // java.lang.Runnable
                                                                            public final void run() {
                                                                                this.f$0.lambda$null$6$NotificationsSettingsActivity(position);
                                                                            }
                                                                        }));
                                                                    } else if (position == this.repeatRow) {
                                                                        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                                                                        builder.setTitle(LocaleController.getString("RepeatNotifications", R.string.RepeatNotifications));
                                                                        builder.setItems(new CharSequence[]{LocaleController.getString("RepeatDisabled", R.string.RepeatDisabled), LocaleController.formatPluralString("Minutes", 5), LocaleController.formatPluralString("Minutes", 10), LocaleController.formatPluralString("Minutes", 30), LocaleController.formatPluralString("Hours", 1), LocaleController.formatPluralString("Hours", 2), LocaleController.formatPluralString("Hours", 4)}, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsSettingsActivity$Ozl3ww0rePKSL6smsb9ApgfUWVM
                                                                            @Override // android.content.DialogInterface.OnClickListener
                                                                            public final void onClick(DialogInterface dialogInterface, int i) {
                                                                                this.f$0.lambda$null$7$NotificationsSettingsActivity(position, dialogInterface, i);
                                                                            }
                                                                        });
                                                                        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                                                                        showDialog(builder.create());
                                                                    }
                                                                } else {
                                                                    SharedPreferences preferences2 = MessagesController.getNotificationsSettings(this.currentAccount);
                                                                    enabled = preferences2.getBoolean("pushService", true);
                                                                    SharedPreferences.Editor editor = preferences2.edit();
                                                                    editor.putBoolean("pushService", !enabled);
                                                                    editor.commit();
                                                                    if (!enabled) {
                                                                        ApplicationLoader.startPushService();
                                                                    } else {
                                                                        ApplicationLoader.stopPushService();
                                                                    }
                                                                }
                                                            } else {
                                                                SharedPreferences preferences3 = MessagesController.getGlobalNotificationsSettings();
                                                                enabled = preferences3.getBoolean("AllAccounts", true);
                                                                SharedPreferences.Editor editor2 = preferences3.edit();
                                                                editor2.putBoolean("AllAccounts", !enabled);
                                                                editor2.commit();
                                                                SharedConfig.showNotificationsForAllAccounts = !enabled;
                                                                for (int a = 0; a < 3; a++) {
                                                                    if (SharedConfig.showNotificationsForAllAccounts) {
                                                                        NotificationsController.getInstance(a).showNotifications();
                                                                    } else if (a == this.currentAccount) {
                                                                        NotificationsController.getInstance(a).showNotifications();
                                                                    } else {
                                                                        NotificationsController.getInstance(a).hideNotifications();
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            SharedPreferences preferences4 = MessagesController.getNotificationsSettings(this.currentAccount);
                                                            enabled = preferences4.getBoolean("pushConnection", true);
                                                            SharedPreferences.Editor editor3 = preferences4.edit();
                                                            editor3.putBoolean("pushConnection", !enabled);
                                                            editor3.commit();
                                                            if (!enabled) {
                                                                ConnectionsManager.getInstance(this.currentAccount).setPushConnectionEnabled(true);
                                                            } else {
                                                                ConnectionsManager.getInstance(this.currentAccount).setPushConnectionEnabled(false);
                                                            }
                                                        }
                                                    } else {
                                                        SharedPreferences preferences5 = MessagesController.getNotificationsSettings(this.currentAccount);
                                                        SharedPreferences.Editor editor4 = preferences5.edit();
                                                        enabled = NotificationsController.getInstance(this.currentAccount).showBadgeMessages;
                                                        NotificationsController.getInstance(this.currentAccount).showBadgeMessages = !enabled;
                                                        editor4.putBoolean("badgeNumberMessages", NotificationsController.getInstance(this.currentAccount).showBadgeMessages);
                                                        editor4.commit();
                                                        NotificationsController.getInstance(this.currentAccount).updateBadge();
                                                    }
                                                } else {
                                                    SharedPreferences preferences6 = MessagesController.getNotificationsSettings(this.currentAccount);
                                                    SharedPreferences.Editor editor5 = preferences6.edit();
                                                    enabled = NotificationsController.getInstance(this.currentAccount).showBadgeMuted;
                                                    NotificationsController.getInstance(this.currentAccount).showBadgeMuted = !enabled;
                                                    editor5.putBoolean("badgeNumberMuted", NotificationsController.getInstance(this.currentAccount).showBadgeMuted);
                                                    editor5.commit();
                                                    NotificationsController.getInstance(this.currentAccount).updateBadge();
                                                }
                                            } else {
                                                SharedPreferences preferences7 = MessagesController.getNotificationsSettings(this.currentAccount);
                                                SharedPreferences.Editor editor6 = preferences7.edit();
                                                enabled = NotificationsController.getInstance(this.currentAccount).showBadgeNumber;
                                                NotificationsController.getInstance(this.currentAccount).showBadgeNumber = !enabled;
                                                editor6.putBoolean("badgeNumber", NotificationsController.getInstance(this.currentAccount).showBadgeNumber);
                                                editor6.commit();
                                                NotificationsController.getInstance(this.currentAccount).updateBadge();
                                            }
                                        } else {
                                            SharedPreferences preferences8 = MessagesController.getNotificationsSettings(this.currentAccount);
                                            SharedPreferences.Editor editor7 = preferences8.edit();
                                            enabled = preferences8.getBoolean("EnableAutoNotifications", false);
                                            editor7.putBoolean("EnableAutoNotifications", !enabled);
                                            editor7.commit();
                                        }
                                    } else {
                                        SharedPreferences preferences9 = MessagesController.getNotificationsSettings(this.currentAccount);
                                        SharedPreferences.Editor editor8 = preferences9.edit();
                                        enabled = preferences9.getBoolean("PinnedMessages", true);
                                        editor8.putBoolean("PinnedMessages", !enabled);
                                        editor8.commit();
                                    }
                                } else {
                                    SharedPreferences preferences10 = MessagesController.getNotificationsSettings(this.currentAccount);
                                    SharedPreferences.Editor editor9 = preferences10.edit();
                                    enabled = preferences10.getBoolean("EnableContactJoined", true);
                                    MessagesController.getInstance(this.currentAccount).enableJoined = !enabled;
                                    editor9.putBoolean("EnableContactJoined", !enabled);
                                    editor9.commit();
                                    TLRPC.TL_account_setContactSignUpNotification req = new TLRPC.TL_account_setContactSignUpNotification();
                                    req.silent = enabled;
                                    ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsSettingsActivity$ghSetlITy_n37UWIPVCyixYcLtE
                                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                            NotificationsSettingsActivity.lambda$null$5(tLObject, tL_error);
                                        }
                                    });
                                }
                            } else {
                                SharedPreferences preferences11 = MessagesController.getNotificationsSettings(this.currentAccount);
                                SharedPreferences.Editor editor10 = preferences11.edit();
                                enabled = preferences11.getBoolean("EnableInAppPriority", false);
                                editor10.putBoolean("EnableInAppPriority", !enabled);
                                editor10.commit();
                            }
                        } else {
                            SharedPreferences preferences12 = MessagesController.getNotificationsSettings(this.currentAccount);
                            SharedPreferences.Editor editor11 = preferences12.edit();
                            enabled = preferences12.getBoolean("EnableInChatSound", true);
                            editor11.putBoolean("EnableInChatSound", !enabled);
                            editor11.commit();
                            NotificationsController.getInstance(this.currentAccount).setInChatSoundEnabled(!enabled);
                        }
                    } else {
                        SharedPreferences preferences13 = MessagesController.getNotificationsSettings(this.currentAccount);
                        SharedPreferences.Editor editor12 = preferences13.edit();
                        enabled = preferences13.getBoolean("EnableInAppPreview", true);
                        editor12.putBoolean("EnableInAppPreview", !enabled);
                        editor12.commit();
                    }
                } else {
                    SharedPreferences preferences14 = MessagesController.getNotificationsSettings(this.currentAccount);
                    SharedPreferences.Editor editor13 = preferences14.edit();
                    enabled = preferences14.getBoolean("EnableInAppVibrate", true);
                    editor13.putBoolean("EnableInAppVibrate", !enabled);
                    editor13.commit();
                }
            } else {
                SharedPreferences preferences15 = MessagesController.getNotificationsSettings(this.currentAccount);
                SharedPreferences.Editor editor14 = preferences15.edit();
                enabled = preferences15.getBoolean("EnableInAppSounds", true);
                editor14.putBoolean("EnableInAppSounds", !enabled);
                editor14.commit();
            }
        } else {
            AlertDialog.Builder builder2 = new AlertDialog.Builder(getParentActivity());
            builder2.setMessage(LocaleController.getString("ResetNotificationsAlert", R.string.ResetNotificationsAlert));
            builder2.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder2.setPositiveButton(LocaleController.getString("Reset", R.string.Reset), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsSettingsActivity$Bh2iCeF5ttXVe0i5yyd4x1S3lfw
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$4$NotificationsSettingsActivity(dialogInterface, i);
                }
            });
            builder2.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder2.create());
        }
        if (view instanceof TextCheckCell) {
            ((TextCheckCell) view).setChecked(!enabled);
        }
    }

    public /* synthetic */ void lambda$null$4$NotificationsSettingsActivity(DialogInterface dialogInterface, int i) {
        if (this.reseting) {
            return;
        }
        this.reseting = true;
        TLRPC.TL_account_resetNotifySettings req = new TLRPC.TL_account_resetNotifySettings();
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsSettingsActivity$sYvzrOYiDtFHAqW1wBbDK06GZ2Y
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$3$NotificationsSettingsActivity(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$null$3$NotificationsSettingsActivity(TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsSettingsActivity$yoSjeYPWflefD5N5HEfU-Kda8ng
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$NotificationsSettingsActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$2$NotificationsSettingsActivity() {
        MessagesController.getInstance(this.currentAccount).enableJoined = true;
        this.reseting = false;
        SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
        SharedPreferences.Editor editor = preferences.edit();
        editor.clear();
        editor.commit();
        this.exceptionChats.clear();
        this.exceptionUsers.clear();
        this.adapter.notifyDataSetChanged();
        if (getParentActivity() != null) {
            ToastUtils.show(R.string.ResetNotificationsText);
        }
    }

    static /* synthetic */ void lambda$null$5(TLObject response, TLRPC.TL_error error) {
    }

    public /* synthetic */ void lambda$null$6$NotificationsSettingsActivity(int position) {
        this.adapter.notifyItemChanged(position);
    }

    public /* synthetic */ void lambda$null$7$NotificationsSettingsActivity(int position, DialogInterface dialog, int which) {
        int minutes = 0;
        if (which == 1) {
            minutes = 5;
        } else if (which == 2) {
            minutes = 10;
        } else if (which == 3) {
            minutes = 30;
        } else if (which == 4) {
            minutes = 60;
        } else if (which == 5) {
            minutes = 120;
        } else if (which == 6) {
            minutes = PsExtractor.VIDEO_STREAM_MASK;
        }
        SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
        preferences.edit().putInt("repeat_messages", minutes).commit();
        this.adapter.notifyItemChanged(position);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
        Ringtone rng;
        if (resultCode == -1) {
            Uri ringtone = (Uri) data.getParcelableExtra("android.intent.extra.ringtone.PICKED_URI");
            String name = null;
            if (ringtone != null && (rng = RingtoneManager.getRingtone(getParentActivity(), ringtone)) != null) {
                if (requestCode == this.callsRingtoneRow) {
                    if (ringtone.equals(Settings.System.DEFAULT_RINGTONE_URI)) {
                        name = LocaleController.getString("DefaultRingtone", R.string.DefaultRingtone);
                    } else {
                        name = rng.getTitle(getParentActivity());
                    }
                } else if (ringtone.equals(Settings.System.DEFAULT_NOTIFICATION_URI)) {
                    name = LocaleController.getString("SoundDefault", R.string.SoundDefault);
                } else {
                    name = rng.getTitle(getParentActivity());
                }
                rng.stop();
            }
            SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
            SharedPreferences.Editor editor = preferences.edit();
            if (requestCode == this.callsRingtoneRow) {
                if (name != null && ringtone != null) {
                    editor.putString("CallsRingtone", name);
                    editor.putString("CallsRingtonePath", ringtone.toString());
                } else {
                    editor.putString("CallsRingtone", "NoSound");
                    editor.putString("CallsRingtonePath", "NoSound");
                }
            }
            editor.commit();
            this.adapter.notifyItemChanged(requestCode);
        }
    }

    private void showExceptionsAlert(int position) {
        final ArrayList<NotificationException> exceptions;
        String alertText = null;
        if (position == this.privateRow) {
            exceptions = this.exceptionUsers;
            if (exceptions != null && !exceptions.isEmpty()) {
                alertText = LocaleController.formatPluralString("ChatsException", exceptions.size());
            }
        } else if (position == this.groupRow) {
            exceptions = this.exceptionChats;
            if (exceptions != null && !exceptions.isEmpty()) {
                alertText = LocaleController.formatPluralString("Groups", exceptions.size());
            }
        } else {
            exceptions = this.exceptionChannels;
            if (exceptions != null && !exceptions.isEmpty()) {
                alertText = LocaleController.formatPluralString("Channels", exceptions.size());
            }
        }
        if (alertText == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        if (exceptions.size() == 1) {
            builder.setMessage(AndroidUtilities.replaceTags(LocaleController.formatString("NotificationsExceptionsSingleAlert", R.string.NotificationsExceptionsSingleAlert, alertText)));
        } else {
            builder.setMessage(AndroidUtilities.replaceTags(LocaleController.formatString("NotificationsExceptionsAlert", R.string.NotificationsExceptionsAlert, alertText)));
        }
        builder.setTitle(LocaleController.getString("NotificationsExceptions", R.string.NotificationsExceptions));
        builder.setNeutralButton(LocaleController.getString("ViewExceptions", R.string.ViewExceptions), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsSettingsActivity$dFjT_EWIQ_zM8hf9_BrSBuvSDoM
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showExceptionsAlert$9$NotificationsSettingsActivity(exceptions, dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("OK", R.string.OK), null);
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$showExceptionsAlert$9$NotificationsSettingsActivity(ArrayList exceptions, DialogInterface dialogInterface, int i) {
        presentFragment(new NotificationsCustomSettingsActivity(-1, exceptions));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.adapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.notificationsSettingsUpdated) {
            this.adapter.notifyDataSetChanged();
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            return (position == NotificationsSettingsActivity.this.notificationsSectionRow || position == NotificationsSettingsActivity.this.notificationsSection2Row || position == NotificationsSettingsActivity.this.inappSectionRow || position == NotificationsSettingsActivity.this.eventsSectionRow || position == NotificationsSettingsActivity.this.otherSectionRow || position == NotificationsSettingsActivity.this.resetSectionRow || position == NotificationsSettingsActivity.this.badgeNumberSection || position == NotificationsSettingsActivity.this.otherSection2Row || position == NotificationsSettingsActivity.this.resetSection2Row || position == NotificationsSettingsActivity.this.callsSection2Row || position == NotificationsSettingsActivity.this.callsSectionRow || position == NotificationsSettingsActivity.this.badgeNumberSection2Row || position == NotificationsSettingsActivity.this.accountsSectionRow || position == NotificationsSettingsActivity.this.accountsInfoRow) ? false : true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return NotificationsSettingsActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                View view2 = new HeaderCell(this.mContext);
                view2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                view = view2;
            } else if (viewType == 1) {
                View view3 = new TextCheckCell(this.mContext);
                view3.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                view = view3;
            } else if (viewType == 2) {
                View view4 = new TextDetailSettingsCell(this.mContext);
                view4.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                view = view4;
            } else if (viewType == 3) {
                View view5 = new NotificationsCheckCell(this.mContext);
                view5.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                view = view5;
            } else if (viewType == 4) {
                view = new ShadowSectionCell(this.mContext);
            } else if (viewType == 5) {
                View view6 = new TextSettingsCell(this.mContext);
                view6.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                view = view6;
            } else {
                view = new TextInfoPrivacyCell(this.mContext);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String text;
            ArrayList<NotificationException> exceptions;
            int offUntil;
            int iconType;
            boolean enabled;
            String value;
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                HeaderCell headerCell = (HeaderCell) holder.itemView;
                if (position != NotificationsSettingsActivity.this.notificationsSectionRow) {
                    if (position != NotificationsSettingsActivity.this.inappSectionRow) {
                        if (position != NotificationsSettingsActivity.this.eventsSectionRow) {
                            if (position != NotificationsSettingsActivity.this.otherSectionRow) {
                                if (position != NotificationsSettingsActivity.this.resetSectionRow) {
                                    if (position != NotificationsSettingsActivity.this.callsSectionRow) {
                                        if (position != NotificationsSettingsActivity.this.badgeNumberSection) {
                                            if (position == NotificationsSettingsActivity.this.accountsSectionRow) {
                                                headerCell.setText(LocaleController.getString("ShowNotificationsFor", R.string.ShowNotificationsFor));
                                                return;
                                            }
                                            return;
                                        }
                                        headerCell.setText(LocaleController.getString("BadgeNumber", R.string.BadgeNumber));
                                        return;
                                    }
                                    headerCell.setText(LocaleController.getString("VoipNotificationSettings", R.string.VoipNotificationSettings));
                                    return;
                                }
                                headerCell.setText(LocaleController.getString("Reset", R.string.Reset));
                                return;
                            }
                            headerCell.setText(LocaleController.getString("NotificationsOther", R.string.NotificationsOther));
                            return;
                        }
                        headerCell.setText(LocaleController.getString("Events", R.string.Events));
                        return;
                    }
                    headerCell.setText(LocaleController.getString("InAppNotifications", R.string.InAppNotifications));
                    return;
                }
                headerCell.setText(LocaleController.getString("NotificationsForChats", R.string.NotificationsForChats));
                return;
            }
            if (itemViewType == 1) {
                TextCheckCell checkCell = (TextCheckCell) holder.itemView;
                SharedPreferences preferences = MessagesController.getNotificationsSettings(NotificationsSettingsActivity.this.currentAccount);
                if (position != NotificationsSettingsActivity.this.inappSoundRow) {
                    if (position != NotificationsSettingsActivity.this.inappVibrateRow) {
                        if (position != NotificationsSettingsActivity.this.inappPreviewRow) {
                            if (position != NotificationsSettingsActivity.this.inappPriorityRow) {
                                if (position != NotificationsSettingsActivity.this.contactJoinedRow) {
                                    if (position != NotificationsSettingsActivity.this.pinnedMessageRow) {
                                        if (position != NotificationsSettingsActivity.this.androidAutoAlertRow) {
                                            if (position != NotificationsSettingsActivity.this.notificationsServiceRow) {
                                                if (position != NotificationsSettingsActivity.this.notificationsServiceConnectionRow) {
                                                    if (position == NotificationsSettingsActivity.this.badgeNumberShowRow) {
                                                        checkCell.setTextAndCheck(LocaleController.getString("BadgeNumberShow", R.string.BadgeNumberShow), NotificationsController.getInstance(NotificationsSettingsActivity.this.currentAccount).showBadgeNumber, true);
                                                        return;
                                                    }
                                                    if (position == NotificationsSettingsActivity.this.badgeNumberMutedRow) {
                                                        checkCell.setTextAndCheck(LocaleController.getString("BadgeNumberMutedChats", R.string.BadgeNumberMutedChats), NotificationsController.getInstance(NotificationsSettingsActivity.this.currentAccount).showBadgeMuted, true);
                                                        return;
                                                    }
                                                    if (position == NotificationsSettingsActivity.this.badgeNumberMessagesRow) {
                                                        checkCell.setTextAndCheck(LocaleController.getString("BadgeNumberUnread", R.string.BadgeNumberUnread), NotificationsController.getInstance(NotificationsSettingsActivity.this.currentAccount).showBadgeMessages, false);
                                                        return;
                                                    }
                                                    if (position != NotificationsSettingsActivity.this.inchatSoundRow) {
                                                        if (position != NotificationsSettingsActivity.this.callsVibrateRow) {
                                                            if (position == NotificationsSettingsActivity.this.accountsAllRow) {
                                                                checkCell.setTextAndCheck(LocaleController.getString("AllAccounts", R.string.AllAccounts), MessagesController.getGlobalNotificationsSettings().getBoolean("AllAccounts", true), false);
                                                                return;
                                                            }
                                                            return;
                                                        }
                                                        checkCell.setTextAndCheck(LocaleController.getString("Vibrate", R.string.Vibrate), preferences.getBoolean("EnableCallVibrate", true), true);
                                                        return;
                                                    }
                                                    checkCell.setTextAndCheck(LocaleController.getString("InChatSound", R.string.InChatSound), preferences.getBoolean("EnableInChatSound", true), true);
                                                    return;
                                                }
                                                checkCell.setTextAndValueAndCheck(LocaleController.getString("NotificationsServiceConnection", R.string.NotificationsServiceConnection), LocaleController.getString("NotificationsServiceConnectionInfo", R.string.NotificationsServiceConnectionInfo), preferences.getBoolean("pushConnection", true), true, true);
                                                return;
                                            }
                                            checkCell.setTextAndValueAndCheck(LocaleController.getString("NotificationsService", R.string.NotificationsService), LocaleController.getString("NotificationsServiceInfo", R.string.NotificationsServiceInfo), preferences.getBoolean("pushService", true), true, true);
                                            return;
                                        }
                                        checkCell.setTextAndCheck("Android Auto", preferences.getBoolean("EnableAutoNotifications", false), true);
                                        return;
                                    }
                                    checkCell.setTextAndCheck(LocaleController.getString("PinnedMessages", R.string.PinnedMessages), preferences.getBoolean("PinnedMessages", true), false);
                                    return;
                                }
                                checkCell.setTextAndCheck(LocaleController.getString("ContactJoined", R.string.ContactJoined), preferences.getBoolean("EnableContactJoined", true), true);
                                return;
                            }
                            checkCell.setTextAndCheck(LocaleController.getString("NotificationsImportance", R.string.NotificationsImportance), preferences.getBoolean("EnableInAppPriority", false), false);
                            return;
                        }
                        checkCell.setTextAndCheck(LocaleController.getString("InAppPreview", R.string.InAppPreview), preferences.getBoolean("EnableInAppPreview", true), true);
                        return;
                    }
                    checkCell.setTextAndCheck(LocaleController.getString("InAppVibrate", R.string.InAppVibrate), preferences.getBoolean("EnableInAppVibrate", true), true);
                    return;
                }
                checkCell.setTextAndCheck(LocaleController.getString("InAppSounds", R.string.InAppSounds), preferences.getBoolean("EnableInAppSounds", true), true);
                return;
            }
            if (itemViewType == 2) {
                TextDetailSettingsCell settingsCell = (TextDetailSettingsCell) holder.itemView;
                settingsCell.setMultilineDetail(true);
                if (position == NotificationsSettingsActivity.this.resetNotificationsRow) {
                    settingsCell.setTextAndValue(LocaleController.getString("ResetAllNotifications", R.string.ResetAllNotifications), LocaleController.getString("UndoAllCustom", R.string.UndoAllCustom), false);
                    return;
                }
                return;
            }
            if (itemViewType != 3) {
                if (itemViewType != 5) {
                    if (itemViewType == 6) {
                        TextInfoPrivacyCell textCell = (TextInfoPrivacyCell) holder.itemView;
                        if (position == NotificationsSettingsActivity.this.accountsInfoRow) {
                            textCell.setText(LocaleController.getString("ShowNotificationsForInfo", R.string.ShowNotificationsForInfo));
                            return;
                        }
                        return;
                    }
                    return;
                }
                TextSettingsCell textCell2 = (TextSettingsCell) holder.itemView;
                SharedPreferences preferences2 = MessagesController.getNotificationsSettings(NotificationsSettingsActivity.this.currentAccount);
                if (position != NotificationsSettingsActivity.this.callsRingtoneRow) {
                    if (position != NotificationsSettingsActivity.this.callsVibrateRow) {
                        if (position == NotificationsSettingsActivity.this.repeatRow) {
                            int minutes = preferences2.getInt("repeat_messages", 60);
                            if (minutes == 0) {
                                value = LocaleController.getString("RepeatNotificationsNever", R.string.RepeatNotificationsNever);
                            } else if (minutes < 60) {
                                value = LocaleController.formatPluralString("Minutes", minutes);
                            } else {
                                value = LocaleController.formatPluralString("Hours", minutes / 60);
                            }
                            textCell2.setTextAndValue(LocaleController.getString("RepeatNotifications", R.string.RepeatNotifications), value, false);
                            return;
                        }
                        return;
                    }
                    int value2 = 0;
                    if (position == NotificationsSettingsActivity.this.callsVibrateRow) {
                        value2 = preferences2.getInt("vibrate_calls", 0);
                    }
                    if (value2 == 0) {
                        textCell2.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("VibrationDefault", R.string.VibrationDefault), true);
                        return;
                    }
                    if (value2 == 1) {
                        textCell2.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("Short", R.string.Short), true);
                        return;
                    }
                    if (value2 == 2) {
                        textCell2.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("VibrationDisabled", R.string.VibrationDisabled), true);
                        return;
                    } else if (value2 == 3) {
                        textCell2.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("Long", R.string.Long), true);
                        return;
                    } else {
                        if (value2 == 4) {
                            textCell2.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("OnlyIfSilent", R.string.OnlyIfSilent), true);
                            return;
                        }
                        return;
                    }
                }
                String value3 = preferences2.getString("CallsRingtone", LocaleController.getString("DefaultRingtone", R.string.DefaultRingtone));
                if (value3.equals("NoSound")) {
                    value3 = LocaleController.getString("NoSound", R.string.NoSound);
                }
                textCell2.setTextAndValue(LocaleController.getString("VoipSettingsRingtone", R.string.VoipSettingsRingtone), value3, false);
                return;
            }
            NotificationsCheckCell checkCell2 = (NotificationsCheckCell) holder.itemView;
            SharedPreferences preferences3 = MessagesController.getNotificationsSettings(NotificationsSettingsActivity.this.currentAccount);
            int currentTime = ConnectionsManager.getInstance(NotificationsSettingsActivity.this.currentAccount).getCurrentTime();
            if (position != NotificationsSettingsActivity.this.privateRow) {
                if (position == NotificationsSettingsActivity.this.groupRow) {
                    String text2 = LocaleController.getString("NotificationsGroups", R.string.NotificationsGroups);
                    ArrayList<NotificationException> exceptions2 = NotificationsSettingsActivity.this.exceptionChats;
                    text = text2;
                    exceptions = exceptions2;
                    offUntil = preferences3.getInt("EnableGroup2", 0);
                } else {
                    String text3 = LocaleController.getString("NotificationsChannels", R.string.NotificationsChannels);
                    ArrayList<NotificationException> exceptions3 = NotificationsSettingsActivity.this.exceptionChannels;
                    text = text3;
                    exceptions = exceptions3;
                    offUntil = preferences3.getInt("EnableChannel2", 0);
                }
            } else {
                String text4 = LocaleController.getString("NotificationsPrivateChats", R.string.NotificationsPrivateChats);
                ArrayList<NotificationException> exceptions4 = NotificationsSettingsActivity.this.exceptionUsers;
                text = text4;
                exceptions = exceptions4;
                offUntil = preferences3.getInt("EnableAll2", 0);
            }
            boolean z = offUntil < currentTime;
            boolean enabled2 = z;
            if (z) {
                iconType = 0;
            } else {
                int iconType2 = offUntil - 31536000;
                if (iconType2 >= currentTime) {
                    iconType = 0;
                } else {
                    iconType = 2;
                }
            }
            StringBuilder builder = new StringBuilder();
            if (exceptions != null && !exceptions.isEmpty()) {
                boolean z2 = offUntil < currentTime;
                boolean enabled3 = z2;
                if (z2) {
                    builder.append(LocaleController.getString("NotificationsOn", R.string.NotificationsOn));
                } else if (offUntil - 31536000 >= currentTime) {
                    builder.append(LocaleController.getString("NotificationsOff", R.string.NotificationsOff));
                } else {
                    builder.append(LocaleController.formatString("NotificationsOffUntil", R.string.NotificationsOffUntil, LocaleController.stringForMessageListDate(offUntil)));
                }
                if (builder.length() != 0) {
                    builder.append(", ");
                }
                builder.append(LocaleController.formatPluralString("Exception", exceptions.size()));
                enabled = enabled3;
            } else {
                builder.append(LocaleController.getString("TapToChange", R.string.TapToChange));
                enabled = enabled2;
            }
            checkCell2.setTextAndValueAndCheck(text, builder, enabled, iconType, position != NotificationsSettingsActivity.this.channelsRow);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != NotificationsSettingsActivity.this.eventsSectionRow && position != NotificationsSettingsActivity.this.otherSectionRow && position != NotificationsSettingsActivity.this.resetSectionRow && position != NotificationsSettingsActivity.this.callsSectionRow && position != NotificationsSettingsActivity.this.badgeNumberSection && position != NotificationsSettingsActivity.this.inappSectionRow && position != NotificationsSettingsActivity.this.notificationsSectionRow && position != NotificationsSettingsActivity.this.accountsSectionRow) {
                if (position != NotificationsSettingsActivity.this.inappSoundRow && position != NotificationsSettingsActivity.this.inappVibrateRow && position != NotificationsSettingsActivity.this.notificationsServiceConnectionRow && position != NotificationsSettingsActivity.this.inappPreviewRow && position != NotificationsSettingsActivity.this.contactJoinedRow && position != NotificationsSettingsActivity.this.pinnedMessageRow && position != NotificationsSettingsActivity.this.notificationsServiceRow && position != NotificationsSettingsActivity.this.badgeNumberMutedRow && position != NotificationsSettingsActivity.this.badgeNumberMessagesRow && position != NotificationsSettingsActivity.this.badgeNumberShowRow && position != NotificationsSettingsActivity.this.inappPriorityRow && position != NotificationsSettingsActivity.this.inchatSoundRow && position != NotificationsSettingsActivity.this.androidAutoAlertRow && position != NotificationsSettingsActivity.this.accountsAllRow) {
                    if (position != NotificationsSettingsActivity.this.resetNotificationsRow) {
                        if (position != NotificationsSettingsActivity.this.privateRow && position != NotificationsSettingsActivity.this.groupRow && position != NotificationsSettingsActivity.this.channelsRow) {
                            if (position != NotificationsSettingsActivity.this.eventsSection2Row && position != NotificationsSettingsActivity.this.notificationsSection2Row && position != NotificationsSettingsActivity.this.otherSection2Row && position != NotificationsSettingsActivity.this.resetSection2Row && position != NotificationsSettingsActivity.this.callsSection2Row && position != NotificationsSettingsActivity.this.badgeNumberSection2Row) {
                                if (position == NotificationsSettingsActivity.this.accountsInfoRow) {
                                    return 6;
                                }
                                return 5;
                            }
                            return 4;
                        }
                        return 3;
                    }
                    return 2;
                }
                return 1;
            }
            return 0;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{HeaderCell.class, TextCheckCell.class, TextDetailSettingsCell.class, TextSettingsCell.class, NotificationsCheckCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrack), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackChecked), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrack), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackChecked), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextDetailSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextDetailSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, ThemeDescription.FLAG_LINKCOLOR, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteLinkText)};
    }
}
