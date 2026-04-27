package im.uwrkaxlmjj.ui.settings;

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.DownloadController;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.ui.ProxyListActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.voip.VoIPHelper;
import im.uwrkaxlmjj.ui.hviews.MrySwitch;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class DataAndStoreSettingActivity extends BaseFragment {

    public interface CallSettingSelectedListener {
        void onSeleted(int i);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        DownloadController.getInstance(this.currentAccount).loadAutoDownloadConfig(true);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setTitle(LocaleController.getString("DataSettings", R.string.DataSettings));
        if (AndroidUtilities.isTablet()) {
            this.actionBar.setOccupyStatusBar(false);
        }
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.settings.DataAndStoreSettingActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    DataAndStoreSettingActivity.this.finishFragment();
                }
            }
        });
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_setting_data_and_store, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initView(context);
        initListener();
        return this.fragmentView;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onDialogDismiss(Dialog dialog) {
        DownloadController.getInstance(this.currentAccount).checkAutodownloadSettings();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        initSettingState();
    }

    private void initView(Context context) {
        this.fragmentView.findViewById(R.attr.rl_store_number).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0, 0, Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_network_number).setBackground(Theme.getRoundRectSelectorDrawable(0, 0, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_use_mobile_network).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0, 0, Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_use_wifi_network).setBackground(Theme.getSelectorDrawable(true));
        this.fragmentView.findViewById(R.attr.rl_reset_download_file).setBackground(Theme.getRoundRectSelectorDrawable(0, 0, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_gif).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0, 0, Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_videos).setBackground(Theme.getRoundRectSelectorDrawable(0, 0, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_use_less_flow).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void initSettingState() {
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_gif)).setChecked(SharedConfig.autoplayGifs, true);
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_videos)).setChecked(SharedConfig.autoplayVideo, true);
        DownloadController controller = DownloadController.getInstance(this.currentAccount);
        boolean blnEnable = (controller.lowPreset.equals(controller.getCurrentRoamingPreset()) && controller.lowPreset.isEnabled() == controller.roamingPreset.enabled && controller.mediumPreset.equals(controller.getCurrentMobilePreset()) && controller.mediumPreset.isEnabled() == controller.mobilePreset.enabled && controller.highPreset.equals(controller.getCurrentWiFiPreset()) && controller.highPreset.isEnabled() == controller.wifiPreset.enabled) ? false : true;
        this.fragmentView.findViewById(R.attr.rl_reset_download_file).setEnabled(blnEnable);
        this.fragmentView.findViewById(R.attr.tv_reset_download_file).setAlpha(blnEnable ? 1.0f : 0.5f);
        setAutoDownloadFileState(0);
        setAutoDownloadFileState(1);
        setUseLessFlowState();
    }

    private void setUseLessFlowState() {
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        String value = null;
        int i = preferences.getInt("VoipDataSaving", VoIPHelper.getDataSavingDefault());
        if (i == 0) {
            value = LocaleController.getString("UseLessDataNever", R.string.UseLessDataNever);
        } else if (i == 1) {
            value = LocaleController.getString("UseLessDataOnMobile", R.string.UseLessDataOnMobile);
        } else if (i == 2) {
            value = LocaleController.getString("UseLessDataAlways", R.string.UseLessDataAlways);
        } else if (i == 3) {
            value = LocaleController.getString("UseLessDataOnRoaming", R.string.UseLessDataOnRoaming);
        }
        ((TextView) this.fragmentView.findViewById(R.attr.tv_use_less_flow)).setText(value);
    }

    private void setAutoDownloadFileState(int iNetWorkType) {
        String text;
        boolean enabled;
        DownloadController.Preset preset;
        StringBuilder builder = new StringBuilder();
        if (iNetWorkType == 0) {
            text = LocaleController.getString("WhenUsingMobileData", R.string.WhenUsingMobileData);
            enabled = DownloadController.getInstance(this.currentAccount).mobilePreset.enabled;
            preset = DownloadController.getInstance(this.currentAccount).getCurrentMobilePreset();
        } else {
            text = LocaleController.getString("WhenConnectedOnWiFi", R.string.WhenConnectedOnWiFi);
            enabled = DownloadController.getInstance(this.currentAccount).wifiPreset.enabled;
            preset = DownloadController.getInstance(this.currentAccount).getCurrentWiFiPreset();
        }
        boolean photos = false;
        boolean videos = false;
        boolean files = false;
        int count = 0;
        for (int a = 0; a < preset.mask.length; a++) {
            if (!photos && (preset.mask[a] & 1) != 0) {
                photos = true;
                count++;
            }
            if (!videos && (preset.mask[a] & 4) != 0) {
                videos = true;
                count++;
            }
            if (!files && (preset.mask[a] & 8) != 0) {
                files = true;
                count++;
            }
        }
        if (preset.enabled && count != 0) {
            if (photos) {
                builder.append(LocaleController.getString("AutoDownloadPhotosOn", R.string.AutoDownloadPhotosOn));
            }
            if (videos) {
                if (builder.length() > 0) {
                    builder.append(", ");
                }
                builder.append(LocaleController.getString("AutoDownloadVideosOn", R.string.AutoDownloadVideosOn));
                builder.append(String.format(" (%1$s)", AndroidUtilities.formatFileSize(preset.sizes[DownloadController.typeToIndex(4)], true)));
            }
            if (files) {
                if (builder.length() > 0) {
                    builder.append(", ");
                }
                builder.append(LocaleController.getString("AutoDownloadFilesOn", R.string.AutoDownloadFilesOn));
                builder.append(String.format(" (%1$s)", AndroidUtilities.formatFileSize(preset.sizes[DownloadController.typeToIndex(8)], true)));
            }
        } else {
            builder.append(LocaleController.getString("NoMediaAutoDownload", R.string.NoMediaAutoDownload));
        }
        if (iNetWorkType == 0) {
            ((TextView) this.fragmentView.findViewById(R.attr.tv_mobile_content_tip)).setText(builder);
        } else {
            ((TextView) this.fragmentView.findViewById(R.attr.tv_wifi_content_tip)).setText(builder);
        }
    }

    private void initListener() {
        this.fragmentView.findViewById(R.attr.rl_store_number).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.DataAndStoreSettingActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                DataAndStoreSettingActivity.this.presentFragment(new CacheControlSettingActivity());
            }
        });
        this.fragmentView.findViewById(R.attr.rl_network_number).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.DataAndStoreSettingActivity.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                DataAndStoreSettingActivity.this.presentFragment(new DataUseStatisticsActivity());
            }
        });
        this.fragmentView.findViewById(R.attr.rl_use_mobile_network).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.DataAndStoreSettingActivity.4
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                DataAndStoreSettingActivity.this.presentFragment(new AutoDownloadSettingActivity(0));
            }
        });
        this.fragmentView.findViewById(R.attr.rl_use_wifi_network).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.DataAndStoreSettingActivity.5
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                DataAndStoreSettingActivity.this.presentFragment(new AutoDownloadSettingActivity(1));
            }
        });
        this.fragmentView.findViewById(R.attr.rl_reset_download_file).setOnClickListener(new AnonymousClass6());
        this.fragmentView.findViewById(R.attr.rl_gif).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.DataAndStoreSettingActivity.7
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                SharedConfig.toggleAutoplayGifs();
                ((MrySwitch) DataAndStoreSettingActivity.this.fragmentView.findViewById(R.attr.switch_gif)).setChecked(SharedConfig.autoplayGifs, true);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_videos).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.DataAndStoreSettingActivity.8
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                SharedConfig.toggleAutoplayVideo();
                ((MrySwitch) DataAndStoreSettingActivity.this.fragmentView.findViewById(R.attr.switch_videos)).setChecked(SharedConfig.autoplayVideo, true);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_use_less_flow).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.DataAndStoreSettingActivity.9
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                final SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                int selected = 0;
                int i = preferences.getInt("VoipDataSaving", VoIPHelper.getDataSavingDefault());
                if (i == 0) {
                    selected = 0;
                } else if (i == 1) {
                    selected = 2;
                } else if (i == 2) {
                    selected = 3;
                } else if (i == 3) {
                    selected = 1;
                }
                DataAndStoreSettingActivity.this.presentFragment(new CallSettingActivity(selected, new CallSettingSelectedListener() { // from class: im.uwrkaxlmjj.ui.settings.DataAndStoreSettingActivity.9.1
                    @Override // im.uwrkaxlmjj.ui.settings.DataAndStoreSettingActivity.CallSettingSelectedListener
                    public void onSeleted(int iSeled) {
                        int val = -1;
                        if (iSeled == 0) {
                            val = 0;
                        } else if (iSeled == 1) {
                            val = 3;
                        } else if (iSeled == 2) {
                            val = 1;
                        } else if (iSeled == 3) {
                            val = 2;
                        }
                        if (val != -1) {
                            preferences.edit().putInt("VoipDataSaving", val).commit();
                        }
                        DataAndStoreSettingActivity.this.initSettingState();
                    }
                }));
            }
        });
        this.fragmentView.findViewById(R.attr.rl_proxy).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.DataAndStoreSettingActivity.10
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                DataAndStoreSettingActivity.this.presentFragment(new ProxyListActivity());
            }
        });
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.settings.DataAndStoreSettingActivity$6, reason: invalid class name */
    class AnonymousClass6 implements View.OnClickListener {
        AnonymousClass6() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            if (DataAndStoreSettingActivity.this.getParentActivity() == null || !view.isEnabled()) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(DataAndStoreSettingActivity.this.getParentActivity());
            builder.setTitle(LocaleController.getString("ResetAutomaticMediaDownloadAlertTitle", R.string.ResetAutomaticMediaDownloadAlertTitle));
            builder.setMessage(LocaleController.getString("ResetAutomaticMediaDownloadAlert", R.string.ResetAutomaticMediaDownloadAlert));
            builder.setPositiveButton(LocaleController.getString("Reset", R.string.Reset), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$DataAndStoreSettingActivity$6$R7iCIROcG2BESuCzbQlu9y0BQtE
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$onClick$0$DataAndStoreSettingActivity$6(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            AlertDialog dialog = builder.create();
            DataAndStoreSettingActivity.this.showDialog(dialog);
            TextView button = (TextView) dialog.getButton(-1);
            if (button != null) {
                button.setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
            }
        }

        public /* synthetic */ void lambda$onClick$0$DataAndStoreSettingActivity$6(DialogInterface dialogInterface, int i) {
            DownloadController.Preset preset;
            DownloadController.Preset defaultPreset;
            String key;
            SharedPreferences.Editor editor = MessagesController.getMainSettings(DataAndStoreSettingActivity.this.currentAccount).edit();
            for (int a = 0; a < 3; a++) {
                if (a == 0) {
                    preset = DownloadController.getInstance(DataAndStoreSettingActivity.this.currentAccount).mobilePreset;
                    defaultPreset = DownloadController.getInstance(DataAndStoreSettingActivity.this.currentAccount).mediumPreset;
                    key = "mobilePreset";
                } else if (a == 1) {
                    preset = DownloadController.getInstance(DataAndStoreSettingActivity.this.currentAccount).wifiPreset;
                    defaultPreset = DownloadController.getInstance(DataAndStoreSettingActivity.this.currentAccount).highPreset;
                    key = "wifiPreset";
                } else {
                    preset = DownloadController.getInstance(DataAndStoreSettingActivity.this.currentAccount).roamingPreset;
                    defaultPreset = DownloadController.getInstance(DataAndStoreSettingActivity.this.currentAccount).lowPreset;
                    key = "roamingPreset";
                }
                preset.set(defaultPreset);
                preset.enabled = defaultPreset.isEnabled();
                DownloadController.getInstance(DataAndStoreSettingActivity.this.currentAccount).currentMobilePreset = 3;
                editor.putInt("currentMobilePreset", 3);
                DownloadController.getInstance(DataAndStoreSettingActivity.this.currentAccount).currentWifiPreset = 3;
                editor.putInt("currentWifiPreset", 3);
                DownloadController.getInstance(DataAndStoreSettingActivity.this.currentAccount).currentRoamingPreset = 3;
                editor.putInt("currentRoamingPreset", 3);
                editor.putString(key, preset.toString());
            }
            editor.commit();
            DownloadController.getInstance(DataAndStoreSettingActivity.this.currentAccount).checkAutodownloadSettings();
            for (int a2 = 0; a2 < 3; a2++) {
                DownloadController.getInstance(DataAndStoreSettingActivity.this.currentAccount).savePresetToServer(a2);
            }
            DataAndStoreSettingActivity.this.initSettingState();
        }
    }
}
