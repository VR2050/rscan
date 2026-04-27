package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
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
import android.os.Bundle;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.exoplayer2.upstream.cache.ContentMetadata;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.NotificationsController;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.NotificationsSettingsActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.RadioCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextCheckBoxCell;
import im.uwrkaxlmjj.ui.cells.TextCheckCell;
import im.uwrkaxlmjj.ui.cells.TextColorCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.cells.UserCell2;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public class ProfileNotificationsActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private static final int done_button = 1;
    private ListAdapter adapter;
    private boolean addingException;
    private AnimatorSet animatorSet;
    private int avatarRow;
    private int avatarSectionRow;
    private int callsRow;
    private int callsVibrateRow;
    private int colorRow;
    private boolean customEnabled;
    private int customInfoRow;
    private int customRow;
    private ProfileNotificationsActivityDelegate delegate;
    private long dialog_id;
    private int enableRow;
    private int generalRow;
    private int ledInfoRow;
    private int ledRow;
    private RecyclerListView listView;
    private boolean notificationsEnabled;
    private int popupDisabledRow;
    private int popupEnabledRow;
    private int popupInfoRow;
    private int popupRow;
    private int previewRow;
    private int priorityInfoRow;
    private int priorityRow;
    private int ringtoneInfoRow;
    private int ringtoneRow;
    private int rowCount;
    private int smartRow;
    private int soundRow;
    private int vibrateRow;

    public interface ProfileNotificationsActivityDelegate {
        void didCreateNewException(NotificationsSettingsActivity.NotificationException notificationException);
    }

    public ProfileNotificationsActivity(Bundle args) {
        super(args);
        this.dialog_id = args.getLong("dialog_id");
        this.addingException = args.getBoolean("exception", false);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        boolean isChannel;
        this.rowCount = 0;
        if (this.addingException) {
            int i = 0 + 1;
            this.rowCount = i;
            this.avatarRow = 0;
            this.rowCount = i + 1;
            this.avatarSectionRow = i;
            this.customRow = -1;
            this.customInfoRow = -1;
        } else {
            this.avatarRow = -1;
            this.avatarSectionRow = -1;
            int i2 = 0 + 1;
            this.rowCount = i2;
            this.customRow = 0;
            this.rowCount = i2 + 1;
            this.customInfoRow = i2;
        }
        int i3 = this.rowCount;
        int i4 = i3 + 1;
        this.rowCount = i4;
        this.generalRow = i3;
        if (this.addingException) {
            this.rowCount = i4 + 1;
            this.enableRow = i4;
        } else {
            this.enableRow = -1;
        }
        if (((int) this.dialog_id) != 0) {
            int i5 = this.rowCount;
            this.rowCount = i5 + 1;
            this.previewRow = i5;
        } else {
            this.previewRow = -1;
        }
        int i6 = this.rowCount;
        int i7 = i6 + 1;
        this.rowCount = i7;
        this.soundRow = i6;
        int i8 = i7 + 1;
        this.rowCount = i8;
        this.vibrateRow = i7;
        if (((int) this.dialog_id) < 0) {
            this.rowCount = i8 + 1;
            this.smartRow = i8;
        } else {
            this.smartRow = -1;
        }
        if (Build.VERSION.SDK_INT >= 21) {
            int i9 = this.rowCount;
            this.rowCount = i9 + 1;
            this.priorityRow = i9;
        } else {
            this.priorityRow = -1;
        }
        int i10 = this.rowCount;
        this.rowCount = i10 + 1;
        this.priorityInfoRow = i10;
        int lower_id = (int) this.dialog_id;
        if (lower_id < 0) {
            TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-lower_id));
            isChannel = ChatObject.isChannel(chat) && !chat.megagroup;
        } else {
            isChannel = false;
        }
        if (lower_id != 0 && !isChannel) {
            int i11 = this.rowCount;
            int i12 = i11 + 1;
            this.rowCount = i12;
            this.popupRow = i11;
            int i13 = i12 + 1;
            this.rowCount = i13;
            this.popupEnabledRow = i12;
            int i14 = i13 + 1;
            this.rowCount = i14;
            this.popupDisabledRow = i13;
            this.rowCount = i14 + 1;
            this.popupInfoRow = i14;
        } else {
            this.popupRow = -1;
            this.popupEnabledRow = -1;
            this.popupDisabledRow = -1;
            this.popupInfoRow = -1;
        }
        if (lower_id > 0) {
            int i15 = this.rowCount;
            int i16 = i15 + 1;
            this.rowCount = i16;
            this.callsRow = i15;
            int i17 = i16 + 1;
            this.rowCount = i17;
            this.callsVibrateRow = i16;
            int i18 = i17 + 1;
            this.rowCount = i18;
            this.ringtoneRow = i17;
            this.rowCount = i18 + 1;
            this.ringtoneInfoRow = i18;
        } else {
            this.callsRow = -1;
            this.callsVibrateRow = -1;
            this.ringtoneRow = -1;
            this.ringtoneInfoRow = -1;
        }
        int i19 = this.rowCount;
        int i20 = i19 + 1;
        this.rowCount = i20;
        this.ledRow = i19;
        int i21 = i20 + 1;
        this.rowCount = i21;
        this.colorRow = i20;
        this.rowCount = i21 + 1;
        this.ledInfoRow = i21;
        SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
        StringBuilder sb = new StringBuilder();
        sb.append(ContentMetadata.KEY_CUSTOM_PREFIX);
        sb.append(this.dialog_id);
        this.customEnabled = preferences.getBoolean(sb.toString(), false) || this.addingException;
        boolean hasOverride = preferences.contains("notify2_" + this.dialog_id);
        int value = preferences.getInt("notify2_" + this.dialog_id, 0);
        if (value == 0) {
            if (hasOverride) {
                this.notificationsEnabled = true;
            } else {
                this.notificationsEnabled = NotificationsController.getInstance(this.currentAccount).isGlobalNotificationsEnabled(this.dialog_id);
            }
        } else if (value == 1) {
            this.notificationsEnabled = true;
        } else if (value == 2) {
            this.notificationsEnabled = false;
        } else {
            this.notificationsEnabled = false;
        }
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.notificationsSettingsUpdated);
        return super.onFragmentCreate();
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
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.ProfileNotificationsActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    if (!ProfileNotificationsActivity.this.addingException && ProfileNotificationsActivity.this.notificationsEnabled && ProfileNotificationsActivity.this.customEnabled) {
                        MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount).edit().putInt("notify2_" + ProfileNotificationsActivity.this.dialog_id, 0).commit();
                    }
                } else if (id == 1) {
                    SharedPreferences preferences = MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount);
                    SharedPreferences.Editor editor = preferences.edit();
                    editor.putBoolean(ContentMetadata.KEY_CUSTOM_PREFIX + ProfileNotificationsActivity.this.dialog_id, true);
                    TLRPC.Dialog dialog = MessagesController.getInstance(ProfileNotificationsActivity.this.currentAccount).dialogs_dict.get(ProfileNotificationsActivity.this.dialog_id);
                    if (ProfileNotificationsActivity.this.notificationsEnabled) {
                        editor.putInt("notify2_" + ProfileNotificationsActivity.this.dialog_id, 0);
                        MessagesStorage.getInstance(ProfileNotificationsActivity.this.currentAccount).setDialogFlags(ProfileNotificationsActivity.this.dialog_id, 0L);
                        if (dialog != null) {
                            dialog.notify_settings = new TLRPC.TL_peerNotifySettings();
                        }
                    } else {
                        editor.putInt("notify2_" + ProfileNotificationsActivity.this.dialog_id, 2);
                        NotificationsController.getInstance(ProfileNotificationsActivity.this.currentAccount).removeNotificationsForDialog(ProfileNotificationsActivity.this.dialog_id);
                        MessagesStorage.getInstance(ProfileNotificationsActivity.this.currentAccount).setDialogFlags(ProfileNotificationsActivity.this.dialog_id, 1L);
                        if (dialog != null) {
                            dialog.notify_settings = new TLRPC.TL_peerNotifySettings();
                            dialog.notify_settings.mute_until = Integer.MAX_VALUE;
                        }
                    }
                    editor.commit();
                    NotificationsController.getInstance(ProfileNotificationsActivity.this.currentAccount).updateServerNotificationsSettings(ProfileNotificationsActivity.this.dialog_id);
                    if (ProfileNotificationsActivity.this.delegate != null) {
                        NotificationsSettingsActivity.NotificationException exception = new NotificationsSettingsActivity.NotificationException();
                        exception.did = ProfileNotificationsActivity.this.dialog_id;
                        exception.hasCustom = true;
                        exception.notify = preferences.getInt("notify2_" + ProfileNotificationsActivity.this.dialog_id, 0);
                        if (exception.notify != 0) {
                            exception.muteUntil = preferences.getInt("notifyuntil_" + ProfileNotificationsActivity.this.dialog_id, 0);
                        }
                        ProfileNotificationsActivity.this.delegate.didCreateNewException(exception);
                    }
                }
                ProfileNotificationsActivity.this.finishFragment();
            }
        });
        if (this.addingException) {
            this.actionBar.setTitle(LocaleController.getString("NotificationsNewException", R.string.NotificationsNewException));
            this.actionBar.createMenu().addItem(1, LocaleController.getString("Done", R.string.Done).toUpperCase());
        } else {
            this.actionBar.setTitle(LocaleController.getString("CustomNotifications", R.string.CustomNotifications));
        }
        this.fragmentView = new FrameLayout(context);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        frameLayout.addView(recyclerListView, LayoutHelper.createFrame(-1, -1.0f));
        RecyclerListView recyclerListView2 = this.listView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.adapter = listAdapter;
        recyclerListView2.setAdapter(listAdapter);
        this.listView.setItemAnimator(null);
        this.listView.setLayoutAnimation(null);
        this.listView.setLayoutManager(new LinearLayoutManager(context) { // from class: im.uwrkaxlmjj.ui.ProfileNotificationsActivity.2
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        });
        this.listView.setOnItemClickListener(new AnonymousClass3(context));
        return this.fragmentView;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ProfileNotificationsActivity$3, reason: invalid class name */
    class AnonymousClass3 implements RecyclerListView.OnItemClickListener {
        final /* synthetic */ Context val$context;

        AnonymousClass3(Context context) {
            this.val$context = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
        public void onItemClick(View view, int position) {
            if (position != ProfileNotificationsActivity.this.customRow || !(view instanceof TextCheckBoxCell)) {
                if (ProfileNotificationsActivity.this.customEnabled && view.isEnabled()) {
                    if (position != ProfileNotificationsActivity.this.soundRow) {
                        if (position != ProfileNotificationsActivity.this.ringtoneRow) {
                            if (position != ProfileNotificationsActivity.this.vibrateRow) {
                                if (position != ProfileNotificationsActivity.this.enableRow) {
                                    if (position != ProfileNotificationsActivity.this.previewRow) {
                                        if (position != ProfileNotificationsActivity.this.callsVibrateRow) {
                                            if (position != ProfileNotificationsActivity.this.priorityRow) {
                                                if (position != ProfileNotificationsActivity.this.smartRow) {
                                                    if (position != ProfileNotificationsActivity.this.colorRow) {
                                                        if (position == ProfileNotificationsActivity.this.popupEnabledRow) {
                                                            SharedPreferences preferences = MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount);
                                                            preferences.edit().putInt("popup_" + ProfileNotificationsActivity.this.dialog_id, 1).commit();
                                                            ((RadioCell) view).setChecked(true, true);
                                                            View view2 = ProfileNotificationsActivity.this.listView.findViewWithTag(2);
                                                            if (view2 != null) {
                                                                ((RadioCell) view2).setChecked(false, true);
                                                                return;
                                                            }
                                                            return;
                                                        }
                                                        if (position == ProfileNotificationsActivity.this.popupDisabledRow) {
                                                            SharedPreferences preferences2 = MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount);
                                                            preferences2.edit().putInt("popup_" + ProfileNotificationsActivity.this.dialog_id, 2).commit();
                                                            ((RadioCell) view).setChecked(true, true);
                                                            View view3 = ProfileNotificationsActivity.this.listView.findViewWithTag(1);
                                                            if (view3 != null) {
                                                                ((RadioCell) view3).setChecked(false, true);
                                                                return;
                                                            }
                                                            return;
                                                        }
                                                        return;
                                                    }
                                                    if (ProfileNotificationsActivity.this.getParentActivity() == null) {
                                                        return;
                                                    }
                                                    ProfileNotificationsActivity profileNotificationsActivity = ProfileNotificationsActivity.this;
                                                    profileNotificationsActivity.showDialog(AlertsCreator.createColorSelectDialog(profileNotificationsActivity.getParentActivity(), ProfileNotificationsActivity.this.dialog_id, -1, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ProfileNotificationsActivity$3$2l3-XL-H4IK8MyDJEgTaJGT-vwk
                                                        @Override // java.lang.Runnable
                                                        public final void run() {
                                                            this.f$0.lambda$onItemClick$5$ProfileNotificationsActivity$3();
                                                        }
                                                    }));
                                                    return;
                                                }
                                                if (ProfileNotificationsActivity.this.getParentActivity() == null) {
                                                    return;
                                                }
                                                final Context context1 = ProfileNotificationsActivity.this.getParentActivity();
                                                SharedPreferences preferences3 = MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount);
                                                int notifyMaxCount = preferences3.getInt("smart_max_count_" + ProfileNotificationsActivity.this.dialog_id, 2);
                                                int notifyDelay = preferences3.getInt("smart_delay_" + ProfileNotificationsActivity.this.dialog_id, JavaScreenCapturer.DEGREE_180);
                                                if (notifyMaxCount == 0) {
                                                    notifyMaxCount = 2;
                                                }
                                                final int selected = ((((notifyDelay / 60) - 1) * 10) + notifyMaxCount) - 1;
                                                RecyclerListView list = new RecyclerListView(ProfileNotificationsActivity.this.getParentActivity());
                                                list.setLayoutManager(new LinearLayoutManager(this.val$context, 1, false));
                                                list.setClipToPadding(true);
                                                list.setAdapter(new RecyclerListView.SelectionAdapter() { // from class: im.uwrkaxlmjj.ui.ProfileNotificationsActivity.3.1
                                                    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
                                                    public int getItemCount() {
                                                        return 100;
                                                    }

                                                    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
                                                    public boolean isEnabled(RecyclerView.ViewHolder holder) {
                                                        return true;
                                                    }

                                                    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
                                                    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
                                                        TextView textView = new TextView(context1) { // from class: im.uwrkaxlmjj.ui.ProfileNotificationsActivity.3.1.1
                                                            @Override // android.widget.TextView, android.view.View
                                                            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                                                                super.onMeasure(View.MeasureSpec.makeMeasureSpec(widthMeasureSpec, 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(48.0f), 1073741824));
                                                            }
                                                        };
                                                        textView.setGravity(17);
                                                        textView.setTextSize(1, 18.0f);
                                                        textView.setSingleLine(true);
                                                        textView.setEllipsize(TextUtils.TruncateAt.END);
                                                        textView.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
                                                        return new RecyclerListView.Holder(textView);
                                                    }

                                                    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
                                                    public void onBindViewHolder(RecyclerView.ViewHolder holder, int position2) {
                                                        TextView textView = (TextView) holder.itemView;
                                                        textView.setTextColor(Theme.getColor(position2 == selected ? Theme.key_dialogTextGray : Theme.key_dialogTextBlack));
                                                        int notifyMaxCount2 = position2 % 10;
                                                        int notifyDelay2 = position2 / 10;
                                                        String times = LocaleController.formatPluralString("Times", notifyMaxCount2 + 1);
                                                        String minutes = LocaleController.formatPluralString("Minutes", notifyDelay2 + 1);
                                                        textView.setText(LocaleController.formatString("SmartNotificationsDetail", R.string.SmartNotificationsDetail, times, minutes));
                                                    }
                                                });
                                                list.setPadding(0, AndroidUtilities.dp(12.0f), 0, AndroidUtilities.dp(8.0f));
                                                list.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ProfileNotificationsActivity$3$vZSNx1zqpgnZjV5hA1B3tRfXdbo
                                                    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
                                                    public final void onItemClick(View view4, int i) {
                                                        this.f$0.lambda$onItemClick$3$ProfileNotificationsActivity$3(view4, i);
                                                    }
                                                });
                                                AlertDialog.Builder builder = new AlertDialog.Builder(ProfileNotificationsActivity.this.getParentActivity());
                                                builder.setTitle(LocaleController.getString("SmartNotificationsAlert", R.string.SmartNotificationsAlert));
                                                builder.setView(list);
                                                builder.setPositiveButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                                                builder.setNegativeButton(LocaleController.getString("SmartNotificationsDisabled", R.string.SmartNotificationsDisabled), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ProfileNotificationsActivity$3$OWhp2NybrNUhwO9usqD-uWLX_Os
                                                    @Override // android.content.DialogInterface.OnClickListener
                                                    public final void onClick(DialogInterface dialogInterface, int i) {
                                                        this.f$0.lambda$onItemClick$4$ProfileNotificationsActivity$3(dialogInterface, i);
                                                    }
                                                });
                                                ProfileNotificationsActivity.this.showDialog(builder.create());
                                                return;
                                            }
                                            ProfileNotificationsActivity profileNotificationsActivity2 = ProfileNotificationsActivity.this;
                                            profileNotificationsActivity2.showDialog(AlertsCreator.createPrioritySelectDialog(profileNotificationsActivity2.getParentActivity(), ProfileNotificationsActivity.this.dialog_id, -1, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ProfileNotificationsActivity$3$LBNP52uNG_8sgYdaWnM34hQ8VLk
                                                @Override // java.lang.Runnable
                                                public final void run() {
                                                    this.f$0.lambda$onItemClick$2$ProfileNotificationsActivity$3();
                                                }
                                            }));
                                            return;
                                        }
                                        ProfileNotificationsActivity profileNotificationsActivity3 = ProfileNotificationsActivity.this;
                                        profileNotificationsActivity3.showDialog(AlertsCreator.createVibrationSelectDialog(profileNotificationsActivity3.getParentActivity(), ProfileNotificationsActivity.this.dialog_id, "calls_vibrate_", new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ProfileNotificationsActivity$3$If_gxV8IX-pUMc5W9NIZuNKrkpc
                                            @Override // java.lang.Runnable
                                            public final void run() {
                                                this.f$0.lambda$onItemClick$1$ProfileNotificationsActivity$3();
                                            }
                                        }));
                                        return;
                                    }
                                    TextCheckCell checkCell = (TextCheckCell) view;
                                    SharedPreferences preferences4 = MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount);
                                    preferences4.edit().putBoolean("content_preview_" + ProfileNotificationsActivity.this.dialog_id, !checkCell.isChecked()).commit();
                                    checkCell.setChecked(true ^ checkCell.isChecked());
                                    return;
                                }
                                TextCheckCell checkCell2 = (TextCheckCell) view;
                                ProfileNotificationsActivity.this.notificationsEnabled = true ^ checkCell2.isChecked();
                                checkCell2.setChecked(ProfileNotificationsActivity.this.notificationsEnabled);
                                ProfileNotificationsActivity.this.checkRowsEnabled();
                                return;
                            }
                            ProfileNotificationsActivity profileNotificationsActivity4 = ProfileNotificationsActivity.this;
                            profileNotificationsActivity4.showDialog(AlertsCreator.createVibrationSelectDialog(profileNotificationsActivity4.getParentActivity(), ProfileNotificationsActivity.this.dialog_id, false, false, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ProfileNotificationsActivity$3$ffp2h5jEgJkfn5J2G_RfNpSe550
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$onItemClick$0$ProfileNotificationsActivity$3();
                                }
                            }));
                            return;
                        }
                        try {
                            Intent tmpIntent = new Intent("android.intent.action.RINGTONE_PICKER");
                            tmpIntent.putExtra("android.intent.extra.ringtone.TYPE", 1);
                            tmpIntent.putExtra("android.intent.extra.ringtone.SHOW_DEFAULT", true);
                            tmpIntent.putExtra("android.intent.extra.ringtone.SHOW_SILENT", true);
                            tmpIntent.putExtra("android.intent.extra.ringtone.DEFAULT_URI", RingtoneManager.getDefaultUri(1));
                            SharedPreferences preferences5 = MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount);
                            Uri currentSound = null;
                            String defaultPath = null;
                            Uri defaultUri = Settings.System.DEFAULT_NOTIFICATION_URI;
                            if (defaultUri != null) {
                                defaultPath = defaultUri.getPath();
                            }
                            String path = preferences5.getString("ringtone_path_" + ProfileNotificationsActivity.this.dialog_id, defaultPath);
                            if (path != null && !path.equals("NoSound")) {
                                currentSound = path.equals(defaultPath) ? defaultUri : Uri.parse(path);
                            }
                            tmpIntent.putExtra("android.intent.extra.ringtone.EXISTING_URI", currentSound);
                            ProfileNotificationsActivity.this.startActivityForResult(tmpIntent, 13);
                            return;
                        } catch (Exception e) {
                            FileLog.e(e);
                            return;
                        }
                    }
                    try {
                        Intent tmpIntent2 = new Intent("android.intent.action.RINGTONE_PICKER");
                        tmpIntent2.putExtra("android.intent.extra.ringtone.TYPE", 2);
                        tmpIntent2.putExtra("android.intent.extra.ringtone.SHOW_DEFAULT", true);
                        tmpIntent2.putExtra("android.intent.extra.ringtone.SHOW_SILENT", true);
                        tmpIntent2.putExtra("android.intent.extra.ringtone.DEFAULT_URI", RingtoneManager.getDefaultUri(2));
                        SharedPreferences preferences6 = MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount);
                        Uri currentSound2 = null;
                        String defaultPath2 = null;
                        Uri defaultUri2 = Settings.System.DEFAULT_NOTIFICATION_URI;
                        if (defaultUri2 != null) {
                            defaultPath2 = defaultUri2.getPath();
                        }
                        String path2 = preferences6.getString("sound_path_" + ProfileNotificationsActivity.this.dialog_id, defaultPath2);
                        if (path2 != null && !path2.equals("NoSound")) {
                            currentSound2 = path2.equals(defaultPath2) ? defaultUri2 : Uri.parse(path2);
                        }
                        tmpIntent2.putExtra("android.intent.extra.ringtone.EXISTING_URI", currentSound2);
                        ProfileNotificationsActivity.this.startActivityForResult(tmpIntent2, 12);
                        return;
                    } catch (Exception e2) {
                        FileLog.e(e2);
                        return;
                    }
                }
                return;
            }
            SharedPreferences preferences7 = MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount);
            ProfileNotificationsActivity profileNotificationsActivity5 = ProfileNotificationsActivity.this;
            profileNotificationsActivity5.customEnabled = true ^ profileNotificationsActivity5.customEnabled;
            ProfileNotificationsActivity profileNotificationsActivity6 = ProfileNotificationsActivity.this;
            profileNotificationsActivity6.notificationsEnabled = profileNotificationsActivity6.customEnabled;
            preferences7.edit().putBoolean(ContentMetadata.KEY_CUSTOM_PREFIX + ProfileNotificationsActivity.this.dialog_id, ProfileNotificationsActivity.this.customEnabled).commit();
            TextCheckBoxCell cell = (TextCheckBoxCell) view;
            cell.setChecked(ProfileNotificationsActivity.this.customEnabled);
            ProfileNotificationsActivity.this.checkRowsEnabled();
        }

        public /* synthetic */ void lambda$onItemClick$0$ProfileNotificationsActivity$3() {
            if (ProfileNotificationsActivity.this.adapter != null) {
                ProfileNotificationsActivity.this.adapter.notifyItemChanged(ProfileNotificationsActivity.this.vibrateRow);
            }
        }

        public /* synthetic */ void lambda$onItemClick$1$ProfileNotificationsActivity$3() {
            if (ProfileNotificationsActivity.this.adapter != null) {
                ProfileNotificationsActivity.this.adapter.notifyItemChanged(ProfileNotificationsActivity.this.callsVibrateRow);
            }
        }

        public /* synthetic */ void lambda$onItemClick$2$ProfileNotificationsActivity$3() {
            if (ProfileNotificationsActivity.this.adapter != null) {
                ProfileNotificationsActivity.this.adapter.notifyItemChanged(ProfileNotificationsActivity.this.priorityRow);
            }
        }

        public /* synthetic */ void lambda$onItemClick$3$ProfileNotificationsActivity$3(View view1, int position1) {
            if (position1 < 0 || position1 >= 100) {
                return;
            }
            int notifyMaxCount1 = (position1 % 10) + 1;
            int notifyDelay1 = (position1 / 10) + 1;
            SharedPreferences preferences1 = MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount);
            preferences1.edit().putInt("smart_max_count_" + ProfileNotificationsActivity.this.dialog_id, notifyMaxCount1).commit();
            preferences1.edit().putInt("smart_delay_" + ProfileNotificationsActivity.this.dialog_id, notifyDelay1 * 60).commit();
            if (ProfileNotificationsActivity.this.adapter != null) {
                ProfileNotificationsActivity.this.adapter.notifyItemChanged(ProfileNotificationsActivity.this.smartRow);
            }
            ProfileNotificationsActivity.this.dismissCurrentDialog();
        }

        public /* synthetic */ void lambda$onItemClick$4$ProfileNotificationsActivity$3(DialogInterface dialog, int which) {
            SharedPreferences preferences12 = MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount);
            preferences12.edit().putInt("smart_max_count_" + ProfileNotificationsActivity.this.dialog_id, 0).commit();
            if (ProfileNotificationsActivity.this.adapter != null) {
                ProfileNotificationsActivity.this.adapter.notifyItemChanged(ProfileNotificationsActivity.this.smartRow);
            }
            ProfileNotificationsActivity.this.dismissCurrentDialog();
        }

        public /* synthetic */ void lambda$onItemClick$5$ProfileNotificationsActivity$3() {
            if (ProfileNotificationsActivity.this.adapter != null) {
                ProfileNotificationsActivity.this.adapter.notifyItemChanged(ProfileNotificationsActivity.this.colorRow);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
        Ringtone rng;
        if (resultCode != -1 || data == null) {
            return;
        }
        Uri ringtone = (Uri) data.getParcelableExtra("android.intent.extra.ringtone.PICKED_URI");
        String name = null;
        if (ringtone != null && (rng = RingtoneManager.getRingtone(ApplicationLoader.applicationContext, ringtone)) != null) {
            if (requestCode == 13) {
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
        if (requestCode == 12) {
            if (name != null) {
                editor.putString("sound_" + this.dialog_id, name);
                editor.putString("sound_path_" + this.dialog_id, ringtone.toString());
            } else {
                editor.putString("sound_" + this.dialog_id, "NoSound");
                editor.putString("sound_path_" + this.dialog_id, "NoSound");
            }
        } else if (requestCode == 13) {
            if (name != null) {
                editor.putString("ringtone_" + this.dialog_id, name);
                editor.putString("ringtone_path_" + this.dialog_id, ringtone.toString());
            } else {
                editor.putString("ringtone_" + this.dialog_id, "NoSound");
                editor.putString("ringtone_path_" + this.dialog_id, "NoSound");
            }
        }
        editor.commit();
        ListAdapter listAdapter = this.adapter;
        if (listAdapter != null) {
            listAdapter.notifyItemChanged(requestCode == 13 ? this.ringtoneRow : this.soundRow);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.notificationsSettingsUpdated) {
            this.adapter.notifyDataSetChanged();
        }
    }

    public void setDelegate(ProfileNotificationsActivityDelegate profileNotificationsActivityDelegate) {
        this.delegate = profileNotificationsActivityDelegate;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkRowsEnabled() {
        int count = this.listView.getChildCount();
        ArrayList<Animator> animators = new ArrayList<>();
        for (int a = 0; a < count; a++) {
            View child = this.listView.getChildAt(a);
            RecyclerListView.Holder holder = (RecyclerListView.Holder) this.listView.getChildViewHolder(child);
            int type = holder.getItemViewType();
            int position = holder.getAdapterPosition();
            if (position != this.customRow && position != this.enableRow && type != 0) {
                boolean z = false;
                if (type == 1) {
                    TextSettingsCell textCell = (TextSettingsCell) holder.itemView;
                    if (this.customEnabled && this.notificationsEnabled) {
                        z = true;
                    }
                    textCell.setEnabled(z, animators);
                } else if (type == 2) {
                    TextInfoPrivacyCell textCell2 = (TextInfoPrivacyCell) holder.itemView;
                    if (this.customEnabled && this.notificationsEnabled) {
                        z = true;
                    }
                    textCell2.setEnabled(z, animators);
                } else if (type == 3) {
                    TextColorCell textCell3 = (TextColorCell) holder.itemView;
                    if (this.customEnabled && this.notificationsEnabled) {
                        z = true;
                    }
                    textCell3.setEnabled(z, animators);
                } else if (type == 4) {
                    RadioCell radioCell = (RadioCell) holder.itemView;
                    if (this.customEnabled && this.notificationsEnabled) {
                        z = true;
                    }
                    radioCell.setEnabled(z, animators);
                } else if (type == 8 && position == this.previewRow) {
                    TextCheckCell checkCell = (TextCheckCell) holder.itemView;
                    if (this.customEnabled && this.notificationsEnabled) {
                        z = true;
                    }
                    checkCell.setEnabled(z, animators);
                }
            }
        }
        if (!animators.isEmpty()) {
            AnimatorSet animatorSet = this.animatorSet;
            if (animatorSet != null) {
                animatorSet.cancel();
            }
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.animatorSet = animatorSet2;
            animatorSet2.playTogether(animators);
            this.animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ProfileNotificationsActivity.4
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animator) {
                    if (animator.equals(ProfileNotificationsActivity.this.animatorSet)) {
                        ProfileNotificationsActivity.this.animatorSet = null;
                    }
                }
            });
            this.animatorSet.setDuration(150L);
            this.animatorSet.start();
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context context;

        public ListAdapter(Context ctx) {
            this.context = ctx;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return ProfileNotificationsActivity.this.rowCount;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            switch (holder.getItemViewType()) {
                case 1:
                case 3:
                case 4:
                    if (!ProfileNotificationsActivity.this.customEnabled || !ProfileNotificationsActivity.this.notificationsEnabled) {
                    }
                    break;
                case 8:
                    if (holder.getAdapterPosition() == ProfileNotificationsActivity.this.previewRow) {
                        if (!ProfileNotificationsActivity.this.customEnabled || !ProfileNotificationsActivity.this.notificationsEnabled) {
                        }
                    }
                    break;
            }
            return true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            switch (viewType) {
                case 0:
                    View view2 = new HeaderCell(this.context);
                    view2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    view = view2;
                    break;
                case 1:
                    View view3 = new TextSettingsCell(this.context);
                    view3.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    view = view3;
                    break;
                case 2:
                    view = new TextInfoPrivacyCell(this.context);
                    break;
                case 3:
                    View view4 = new TextColorCell(this.context);
                    view4.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    view = view4;
                    break;
                case 4:
                    View view5 = new RadioCell(this.context);
                    view5.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    view = view5;
                    break;
                case 5:
                    View view6 = new TextCheckBoxCell(this.context);
                    view6.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    view = view6;
                    break;
                case 6:
                    View view7 = new UserCell2(this.context, 4, 0);
                    view7.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    view = view7;
                    break;
                case 7:
                    view = new ShadowSectionCell(this.context);
                    break;
                default:
                    View view8 = new TextCheckCell(this.context);
                    view8.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    view = view8;
                    break;
            }
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int color;
            switch (holder.getItemViewType()) {
                case 0:
                    HeaderCell headerCell = (HeaderCell) holder.itemView;
                    if (position != ProfileNotificationsActivity.this.generalRow) {
                        if (position != ProfileNotificationsActivity.this.popupRow) {
                            if (position != ProfileNotificationsActivity.this.ledRow) {
                                if (position == ProfileNotificationsActivity.this.callsRow) {
                                    headerCell.setText(LocaleController.getString("VoipNotificationSettings", R.string.VoipNotificationSettings));
                                }
                            } else {
                                headerCell.setText(LocaleController.getString("NotificationsLed", R.string.NotificationsLed));
                            }
                        } else {
                            headerCell.setText(LocaleController.getString("ProfilePopupNotification", R.string.ProfilePopupNotification));
                        }
                    } else {
                        headerCell.setText(LocaleController.getString("General", R.string.General));
                    }
                    break;
                case 1:
                    TextSettingsCell textCell = (TextSettingsCell) holder.itemView;
                    SharedPreferences preferences = MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount);
                    if (position != ProfileNotificationsActivity.this.soundRow) {
                        if (position != ProfileNotificationsActivity.this.ringtoneRow) {
                            if (position != ProfileNotificationsActivity.this.vibrateRow) {
                                if (position == ProfileNotificationsActivity.this.priorityRow) {
                                    int value = preferences.getInt("priority_" + ProfileNotificationsActivity.this.dialog_id, 3);
                                    if (value == 0) {
                                        textCell.setTextAndValue(LocaleController.getString("NotificationsImportance", R.string.NotificationsImportance), LocaleController.getString("NotificationsPriorityHigh", R.string.NotificationsPriorityHigh), false);
                                    } else if (value == 1 || value == 2) {
                                        textCell.setTextAndValue(LocaleController.getString("NotificationsImportance", R.string.NotificationsImportance), LocaleController.getString("NotificationsPriorityUrgent", R.string.NotificationsPriorityUrgent), false);
                                    } else if (value == 3) {
                                        textCell.setTextAndValue(LocaleController.getString("NotificationsImportance", R.string.NotificationsImportance), LocaleController.getString("NotificationsPrioritySettings", R.string.NotificationsPrioritySettings), false);
                                    } else if (value == 4) {
                                        textCell.setTextAndValue(LocaleController.getString("NotificationsImportance", R.string.NotificationsImportance), LocaleController.getString("NotificationsPriorityLow", R.string.NotificationsPriorityLow), false);
                                    } else if (value == 5) {
                                        textCell.setTextAndValue(LocaleController.getString("NotificationsImportance", R.string.NotificationsImportance), LocaleController.getString("NotificationsPriorityMedium", R.string.NotificationsPriorityMedium), false);
                                    }
                                } else if (position == ProfileNotificationsActivity.this.smartRow) {
                                    int notifyMaxCount = preferences.getInt("smart_max_count_" + ProfileNotificationsActivity.this.dialog_id, 2);
                                    int notifyDelay = preferences.getInt("smart_delay_" + ProfileNotificationsActivity.this.dialog_id, JavaScreenCapturer.DEGREE_180);
                                    if (notifyMaxCount == 0) {
                                        textCell.setTextAndValue(LocaleController.getString("SmartNotifications", R.string.SmartNotifications), LocaleController.getString("SmartNotificationsDisabled", R.string.SmartNotificationsDisabled), ProfileNotificationsActivity.this.priorityRow != -1);
                                    } else {
                                        String minutes = LocaleController.formatPluralString("Minutes", notifyDelay / 60);
                                        textCell.setTextAndValue(LocaleController.getString("SmartNotifications", R.string.SmartNotifications), LocaleController.formatString("SmartNotificationsInfo", R.string.SmartNotificationsInfo, Integer.valueOf(notifyMaxCount), minutes), ProfileNotificationsActivity.this.priorityRow != -1);
                                    }
                                } else if (position == ProfileNotificationsActivity.this.callsVibrateRow) {
                                    int value2 = preferences.getInt("calls_vibrate_" + ProfileNotificationsActivity.this.dialog_id, 0);
                                    if (value2 == 0 || value2 == 4) {
                                        boolean z = true;
                                        textCell.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("VibrationDefault", R.string.VibrationDefault), z);
                                    } else if (value2 == 1) {
                                        textCell.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("Short", R.string.Short), true);
                                    } else if (value2 == 2) {
                                        textCell.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("VibrationDisabled", R.string.VibrationDisabled), true);
                                    } else if (value2 == 3) {
                                        textCell.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("Long", R.string.Long), true);
                                    }
                                }
                            } else {
                                int value3 = preferences.getInt("vibrate_" + ProfileNotificationsActivity.this.dialog_id, 0);
                                if (value3 == 0 || value3 == 4) {
                                    textCell.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("VibrationDefault", R.string.VibrationDefault), (ProfileNotificationsActivity.this.smartRow == -1 && ProfileNotificationsActivity.this.priorityRow == -1) ? false : true);
                                } else if (value3 == 1) {
                                    textCell.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("Short", R.string.Short), (ProfileNotificationsActivity.this.smartRow == -1 && ProfileNotificationsActivity.this.priorityRow == -1) ? false : true);
                                } else if (value3 == 2) {
                                    textCell.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("VibrationDisabled", R.string.VibrationDisabled), (ProfileNotificationsActivity.this.smartRow == -1 && ProfileNotificationsActivity.this.priorityRow == -1) ? false : true);
                                } else if (value3 == 3) {
                                    textCell.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("Long", R.string.Long), (ProfileNotificationsActivity.this.smartRow == -1 && ProfileNotificationsActivity.this.priorityRow == -1) ? false : true);
                                }
                            }
                        } else {
                            String value4 = preferences.getString("ringtone_" + ProfileNotificationsActivity.this.dialog_id, LocaleController.getString("DefaultRingtone", R.string.DefaultRingtone));
                            if (value4.equals("NoSound")) {
                                value4 = LocaleController.getString("NoSound", R.string.NoSound);
                            }
                            textCell.setTextAndValue(LocaleController.getString("VoipSettingsRingtone", R.string.VoipSettingsRingtone), value4, false);
                        }
                    } else {
                        String value5 = preferences.getString("sound_" + ProfileNotificationsActivity.this.dialog_id, LocaleController.getString("SoundDefault", R.string.SoundDefault));
                        if (value5.equals("NoSound")) {
                            value5 = LocaleController.getString("NoSound", R.string.NoSound);
                        }
                        textCell.setTextAndValue(LocaleController.getString("Sound", R.string.Sound), value5, true);
                    }
                    break;
                case 2:
                    TextInfoPrivacyCell textCell2 = (TextInfoPrivacyCell) holder.itemView;
                    if (position != ProfileNotificationsActivity.this.popupInfoRow) {
                        if (position != ProfileNotificationsActivity.this.ledInfoRow) {
                            if (position == ProfileNotificationsActivity.this.priorityInfoRow) {
                                if (ProfileNotificationsActivity.this.priorityRow == -1) {
                                    textCell2.setText("");
                                } else {
                                    textCell2.setText(LocaleController.getString("PriorityInfo", R.string.PriorityInfo));
                                }
                                textCell2.setBackgroundDrawable(Theme.getThemedDrawable(this.context, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                            } else if (position != ProfileNotificationsActivity.this.customInfoRow) {
                                if (position == ProfileNotificationsActivity.this.ringtoneInfoRow) {
                                    textCell2.setText(LocaleController.getString("VoipRingtoneInfo", R.string.VoipRingtoneInfo));
                                    textCell2.setBackgroundDrawable(Theme.getThemedDrawable(this.context, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                                }
                            } else {
                                textCell2.setText(null);
                                textCell2.setBackgroundDrawable(Theme.getThemedDrawable(this.context, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                            }
                        } else {
                            textCell2.setText(LocaleController.getString("NotificationsLedInfo", R.string.NotificationsLedInfo));
                            textCell2.setBackgroundDrawable(Theme.getThemedDrawable(this.context, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                        }
                    } else {
                        textCell2.setText(LocaleController.getString("ProfilePopupNotificationInfo", R.string.ProfilePopupNotificationInfo));
                        textCell2.setBackgroundDrawable(Theme.getThemedDrawable(this.context, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                    }
                    break;
                case 3:
                    TextColorCell textCell3 = (TextColorCell) holder.itemView;
                    SharedPreferences preferences2 = MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount);
                    if (preferences2.contains("color_" + ProfileNotificationsActivity.this.dialog_id)) {
                        color = preferences2.getInt("color_" + ProfileNotificationsActivity.this.dialog_id, -16776961);
                    } else if (((int) ProfileNotificationsActivity.this.dialog_id) < 0) {
                        color = preferences2.getInt("GroupLed", -16776961);
                    } else {
                        color = preferences2.getInt("MessagesLed", -16776961);
                    }
                    int a = 0;
                    while (true) {
                        if (a < 9) {
                            if (TextColorCell.colorsToSave[a] != color) {
                                a++;
                            } else {
                                color = TextColorCell.colors[a];
                            }
                        }
                    }
                    textCell3.setTextAndColor(LocaleController.getString("NotificationsLedColor", R.string.NotificationsLedColor), color, false);
                    break;
                case 4:
                    RadioCell radioCell = (RadioCell) holder.itemView;
                    SharedPreferences preferences3 = MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount);
                    int popup = preferences3.getInt("popup_" + ProfileNotificationsActivity.this.dialog_id, 0);
                    if (popup == 0) {
                        if (preferences3.getInt(((int) ProfileNotificationsActivity.this.dialog_id) < 0 ? "popupGroup" : "popupAll", 0) != 0) {
                            popup = 1;
                        } else {
                            popup = 2;
                        }
                    }
                    if (position != ProfileNotificationsActivity.this.popupEnabledRow) {
                        if (position == ProfileNotificationsActivity.this.popupDisabledRow) {
                            radioCell.setText(LocaleController.getString("PopupDisabled", R.string.PopupDisabled), popup == 2, false);
                            radioCell.setTag(2);
                        }
                    } else {
                        radioCell.setText(LocaleController.getString("PopupEnabled", R.string.PopupEnabled), popup == 1, true);
                        radioCell.setTag(1);
                    }
                    break;
                case 5:
                    TextCheckBoxCell cell = (TextCheckBoxCell) holder.itemView;
                    MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount);
                    cell.setTextAndCheck(LocaleController.getString("NotificationsEnableCustom", R.string.NotificationsEnableCustom), ProfileNotificationsActivity.this.customEnabled && ProfileNotificationsActivity.this.notificationsEnabled, false);
                    break;
                case 6:
                    UserCell2 userCell2 = (UserCell2) holder.itemView;
                    int lower_id = (int) ProfileNotificationsActivity.this.dialog_id;
                    TLObject object = lower_id > 0 ? MessagesController.getInstance(ProfileNotificationsActivity.this.currentAccount).getUser(Integer.valueOf(lower_id)) : MessagesController.getInstance(ProfileNotificationsActivity.this.currentAccount).getChat(Integer.valueOf(-lower_id));
                    userCell2.setData(object, null, null, 0);
                    break;
                case 8:
                    TextCheckCell checkCell = (TextCheckCell) holder.itemView;
                    SharedPreferences preferences4 = MessagesController.getNotificationsSettings(ProfileNotificationsActivity.this.currentAccount);
                    if (position == ProfileNotificationsActivity.this.enableRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("Notifications", R.string.Notifications), ProfileNotificationsActivity.this.notificationsEnabled, true);
                    } else if (position == ProfileNotificationsActivity.this.previewRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("MessagePreview", R.string.MessagePreview), preferences4.getBoolean("content_preview_" + ProfileNotificationsActivity.this.dialog_id, true), true);
                    }
                    break;
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewAttachedToWindow(RecyclerView.ViewHolder holder) {
            if (holder.getItemViewType() != 0) {
                int itemViewType = holder.getItemViewType();
                boolean z = false;
                if (itemViewType == 1) {
                    TextSettingsCell textCell = (TextSettingsCell) holder.itemView;
                    if (ProfileNotificationsActivity.this.customEnabled && ProfileNotificationsActivity.this.notificationsEnabled) {
                        z = true;
                    }
                    textCell.setEnabled(z, null);
                    return;
                }
                if (itemViewType == 2) {
                    TextInfoPrivacyCell textCell2 = (TextInfoPrivacyCell) holder.itemView;
                    if (ProfileNotificationsActivity.this.customEnabled && ProfileNotificationsActivity.this.notificationsEnabled) {
                        z = true;
                    }
                    textCell2.setEnabled(z, null);
                    return;
                }
                if (itemViewType == 3) {
                    TextColorCell textCell3 = (TextColorCell) holder.itemView;
                    if (ProfileNotificationsActivity.this.customEnabled && ProfileNotificationsActivity.this.notificationsEnabled) {
                        z = true;
                    }
                    textCell3.setEnabled(z, null);
                    return;
                }
                if (itemViewType == 4) {
                    RadioCell radioCell = (RadioCell) holder.itemView;
                    if (ProfileNotificationsActivity.this.customEnabled && ProfileNotificationsActivity.this.notificationsEnabled) {
                        z = true;
                    }
                    radioCell.setEnabled(z, null);
                    return;
                }
                if (itemViewType == 8) {
                    TextCheckCell checkCell = (TextCheckCell) holder.itemView;
                    if (holder.getAdapterPosition() == ProfileNotificationsActivity.this.previewRow) {
                        if (ProfileNotificationsActivity.this.customEnabled && ProfileNotificationsActivity.this.notificationsEnabled) {
                            z = true;
                        }
                        checkCell.setEnabled(z, null);
                        return;
                    }
                    checkCell.setEnabled(true, null);
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == ProfileNotificationsActivity.this.generalRow || position == ProfileNotificationsActivity.this.popupRow || position == ProfileNotificationsActivity.this.ledRow || position == ProfileNotificationsActivity.this.callsRow) {
                return 0;
            }
            if (position != ProfileNotificationsActivity.this.soundRow && position != ProfileNotificationsActivity.this.vibrateRow && position != ProfileNotificationsActivity.this.priorityRow && position != ProfileNotificationsActivity.this.smartRow && position != ProfileNotificationsActivity.this.ringtoneRow && position != ProfileNotificationsActivity.this.callsVibrateRow) {
                if (position != ProfileNotificationsActivity.this.popupInfoRow && position != ProfileNotificationsActivity.this.ledInfoRow && position != ProfileNotificationsActivity.this.priorityInfoRow && position != ProfileNotificationsActivity.this.customInfoRow && position != ProfileNotificationsActivity.this.ringtoneInfoRow) {
                    if (position != ProfileNotificationsActivity.this.colorRow) {
                        if (position != ProfileNotificationsActivity.this.popupEnabledRow && position != ProfileNotificationsActivity.this.popupDisabledRow) {
                            if (position != ProfileNotificationsActivity.this.customRow) {
                                if (position != ProfileNotificationsActivity.this.avatarRow) {
                                    if (position == ProfileNotificationsActivity.this.avatarSectionRow) {
                                        return 7;
                                    }
                                    return (position == ProfileNotificationsActivity.this.enableRow || position == ProfileNotificationsActivity.this.previewRow) ? 8 : 0;
                                }
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
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ProfileNotificationsActivity$GnDE57e-O77ZxTpn0iNSS1mhr7U
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$0$ProfileNotificationsActivity();
            }
        };
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{HeaderCell.class, TextSettingsCell.class, TextColorCell.class, RadioCell.class, UserCell2.class, TextCheckCell.class, TextCheckBoxCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, 0, new Class[]{TextColorCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{RadioCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKBOX, new Class[]{RadioCell.class}, new String[]{"radioButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_radioBackground), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKBOXCHECK, new Class[]{RadioCell.class}, new String[]{"radioButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_radioBackgroundChecked), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrack), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackChecked), new ThemeDescription(this.listView, 0, new Class[]{UserCell2.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{UserCell2.class}, new String[]{"statusColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteGrayText), new ThemeDescription(this.listView, 0, new Class[]{UserCell2.class}, new String[]{"statusOnlineColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteBlueText), new ThemeDescription(this.listView, 0, new Class[]{UserCell2.class}, null, new Drawable[]{Theme.avatar_savedDrawable}, null, Theme.key_avatar_text), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundRed), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundOrange), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundViolet), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundGreen), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundCyan), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundBlue), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundPink), new ThemeDescription(this.listView, 0, new Class[]{TextCheckBoxCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextCheckBoxCell.class}, null, null, null, Theme.key_checkboxSquareUnchecked), new ThemeDescription(this.listView, 0, new Class[]{TextCheckBoxCell.class}, null, null, null, Theme.key_checkboxSquareDisabled), new ThemeDescription(this.listView, 0, new Class[]{TextCheckBoxCell.class}, null, null, null, Theme.key_checkboxSquareBackground), new ThemeDescription(this.listView, 0, new Class[]{TextCheckBoxCell.class}, null, null, null, Theme.key_checkboxSquareCheck)};
    }

    public /* synthetic */ void lambda$getThemeDescriptions$0$ProfileNotificationsActivity() {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            int count = recyclerListView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = this.listView.getChildAt(a);
                if (child instanceof UserCell2) {
                    ((UserCell2) child).update(0);
                }
            }
        }
    }
}
