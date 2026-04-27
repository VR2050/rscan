package im.uwrkaxlmjj.ui.settings;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.hviews.MrySwitch;
import im.uwrkaxlmjj.ui.settings.AutoDownloadSettingActivity;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PhotoAutoDownloadSettingActivity extends BaseFragment {
    private static final int SAVE_BUTTON = 1;
    private List<Boolean> mArrList;
    private AutoDownloadSettingActivity.activityButtonClickListener mListener;
    private MrySwitch mswitch_channel;
    private MrySwitch mswitch_contact;
    private MrySwitch mswitch_group_chat;
    private MrySwitch mswitch_private_chat;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setTitle(LocaleController.getString("AttachPhoto", R.string.AttachPhoto));
        if (AndroidUtilities.isTablet()) {
            this.actionBar.setOccupyStatusBar(false);
        }
        this.actionBar.setAllowOverlayTitle(true);
        ActionBarMenu menu = this.actionBar.createMenu();
        menu.addRightItemView(1, LocaleController.getString("Save", R.string.Save));
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_setting_auto_download_photo, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initView(context);
        initListener();
        return this.fragmentView;
    }

    private void initListener() {
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.settings.PhotoAutoDownloadSettingActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    PhotoAutoDownloadSettingActivity.this.finishFragment();
                } else if (id == 1) {
                    if (PhotoAutoDownloadSettingActivity.this.mListener != null) {
                        PhotoAutoDownloadSettingActivity.this.mListener.onSaveBtnClick(PhotoAutoDownloadSettingActivity.this.mArrList, 0L, false);
                    }
                    PhotoAutoDownloadSettingActivity.this.finishFragment();
                }
            }
        });
        this.fragmentView.findViewById(R.attr.rl_contact).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.PhotoAutoDownloadSettingActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                PhotoAutoDownloadSettingActivity.this.mswitch_contact.setChecked(!PhotoAutoDownloadSettingActivity.this.mswitch_contact.isChecked(), true);
                PhotoAutoDownloadSettingActivity.this.mArrList.set(0, Boolean.valueOf(PhotoAutoDownloadSettingActivity.this.mswitch_contact.isChecked()));
            }
        });
        this.fragmentView.findViewById(R.attr.rl_private_chat).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.PhotoAutoDownloadSettingActivity.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                PhotoAutoDownloadSettingActivity.this.mswitch_private_chat.setChecked(!PhotoAutoDownloadSettingActivity.this.mswitch_private_chat.isChecked(), true);
                PhotoAutoDownloadSettingActivity.this.mArrList.set(1, Boolean.valueOf(PhotoAutoDownloadSettingActivity.this.mswitch_private_chat.isChecked()));
            }
        });
        this.fragmentView.findViewById(R.attr.rl_group_chat).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.PhotoAutoDownloadSettingActivity.4
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                PhotoAutoDownloadSettingActivity.this.mswitch_group_chat.setChecked(!PhotoAutoDownloadSettingActivity.this.mswitch_group_chat.isChecked(), true);
                PhotoAutoDownloadSettingActivity.this.mArrList.set(2, Boolean.valueOf(PhotoAutoDownloadSettingActivity.this.mswitch_group_chat.isChecked()));
            }
        });
        this.fragmentView.findViewById(R.attr.rl_channel).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.PhotoAutoDownloadSettingActivity.5
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                PhotoAutoDownloadSettingActivity.this.mswitch_channel.setChecked(!PhotoAutoDownloadSettingActivity.this.mswitch_channel.isChecked(), true);
                PhotoAutoDownloadSettingActivity.this.mArrList.set(3, Boolean.valueOf(PhotoAutoDownloadSettingActivity.this.mswitch_channel.isChecked()));
            }
        });
    }

    private void initView(Context context) {
        this.mswitch_private_chat = (MrySwitch) this.fragmentView.findViewById(R.attr.switch_private_chat);
        this.mswitch_contact = (MrySwitch) this.fragmentView.findViewById(R.attr.switch_contact);
        this.mswitch_group_chat = (MrySwitch) this.fragmentView.findViewById(R.attr.switch_group_chat);
        this.mswitch_channel = (MrySwitch) this.fragmentView.findViewById(R.attr.switch_channel);
        if (this.mArrList != null) {
            for (int i = 0; i < this.mArrList.size(); i++) {
                if (i == 0) {
                    this.mswitch_contact.setChecked(this.mArrList.get(i).booleanValue(), true);
                } else if (i == 1) {
                    this.mswitch_private_chat.setChecked(this.mArrList.get(i).booleanValue(), true);
                } else if (i == 2) {
                    this.mswitch_group_chat.setChecked(this.mArrList.get(i).booleanValue(), true);
                } else if (i == 3) {
                    this.mswitch_channel.setChecked(this.mArrList.get(i).booleanValue(), true);
                }
            }
        }
        this.fragmentView.findViewById(R.attr.rl_contact).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0, 0, Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_private_chat).setBackground(Theme.getSelectorDrawable(true));
        this.fragmentView.findViewById(R.attr.rl_group_chat).setBackground(Theme.getSelectorDrawable(true));
        this.fragmentView.findViewById(R.attr.rl_channel).setBackground(Theme.getRoundRectSelectorDrawable(0, 0, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
    }

    public PhotoAutoDownloadSettingActivity(List<Boolean> arrList, AutoDownloadSettingActivity.activityButtonClickListener listener) {
        this.mListener = null;
        this.mArrList = arrList;
        this.mListener = listener;
    }
}
