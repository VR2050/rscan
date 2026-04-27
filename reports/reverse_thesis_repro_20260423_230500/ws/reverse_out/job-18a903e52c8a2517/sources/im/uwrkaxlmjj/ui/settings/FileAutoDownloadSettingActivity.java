package im.uwrkaxlmjj.ui.settings;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.MaxFileSizeCell;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.hviews.MrySwitch;
import im.uwrkaxlmjj.ui.settings.AutoDownloadSettingActivity;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FileAutoDownloadSettingActivity extends BaseFragment {
    private static final int SAVE_BUTTON = 1;
    private List<Boolean> mArrList;
    private AutoDownloadSettingActivity.activityButtonClickListener mListener;
    private long mSize;
    private MrySwitch mswitch_channel;
    private MrySwitch mswitch_contact;
    private MrySwitch mswitch_group_chat;
    private MrySwitch mswitch_private_chat;
    private final MaxFileSizeCell[] sizeCell = new MaxFileSizeCell[1];
    private FrameLayout mFrameLayout = null;

    public FileAutoDownloadSettingActivity(List<Boolean> arrList, long lsize, AutoDownloadSettingActivity.activityButtonClickListener listener) {
        this.mSize = 0L;
        this.mListener = null;
        this.mArrList = arrList;
        this.mSize = lsize;
        this.mListener = listener;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setTitle(LocaleController.getString("AutoDownloadFilesOn", R.string.AutoDownloadFilesOn));
        if (AndroidUtilities.isTablet()) {
            this.actionBar.setOccupyStatusBar(false);
        }
        this.actionBar.setAllowOverlayTitle(true);
        ActionBarMenu menu = this.actionBar.createMenu();
        menu.addRightItemView(1, LocaleController.getString("Save", R.string.Save));
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_setting_auto_download_file, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initView(context);
        initListener();
        return this.fragmentView;
    }

    private void initView(Context context) {
        this.mFrameLayout = (FrameLayout) this.fragmentView.findViewById(R.attr.fl_container);
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
        this.sizeCell[0] = new MaxFileSizeCell(getParentActivity(), false) { // from class: im.uwrkaxlmjj.ui.settings.FileAutoDownloadSettingActivity.1
            @Override // im.uwrkaxlmjj.ui.cells.MaxFileSizeCell
            protected void didChangedSizeValue(int value) {
            }
        };
        this.sizeCell[0].setSize(this.mSize);
        this.mFrameLayout.addView(this.sizeCell[0], LayoutHelper.createLinear(-1, 50));
        this.mFrameLayout.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.sizeCell[0].setText(LocaleController.getString("AutoDownloadMaxFileSize", R.string.AutoDownloadMaxFileSize));
        this.fragmentView.findViewById(R.attr.rl_contact).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0, 0, Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_private_chat).setBackground(Theme.getSelectorDrawable(true));
        this.fragmentView.findViewById(R.attr.rl_group_chat).setBackground(Theme.getSelectorDrawable(true));
        this.fragmentView.findViewById(R.attr.rl_channel).setBackground(Theme.getRoundRectSelectorDrawable(0, 0, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
    }

    private void initListener() {
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.settings.FileAutoDownloadSettingActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    FileAutoDownloadSettingActivity.this.finishFragment();
                }
                if (id == 1) {
                    if (FileAutoDownloadSettingActivity.this.mListener != null) {
                        FileAutoDownloadSettingActivity.this.mListener.onSaveBtnClick(FileAutoDownloadSettingActivity.this.mArrList, FileAutoDownloadSettingActivity.this.sizeCell[0].getSize(), false);
                    }
                    FileAutoDownloadSettingActivity.this.finishFragment();
                }
            }
        });
        this.fragmentView.findViewById(R.attr.rl_contact).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.FileAutoDownloadSettingActivity.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                FileAutoDownloadSettingActivity.this.mswitch_contact.setChecked(!FileAutoDownloadSettingActivity.this.mswitch_contact.isChecked(), true);
                FileAutoDownloadSettingActivity.this.mArrList.set(0, Boolean.valueOf(FileAutoDownloadSettingActivity.this.mswitch_contact.isChecked()));
            }
        });
        this.fragmentView.findViewById(R.attr.rl_private_chat).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.FileAutoDownloadSettingActivity.4
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                FileAutoDownloadSettingActivity.this.mswitch_private_chat.setChecked(!FileAutoDownloadSettingActivity.this.mswitch_private_chat.isChecked(), true);
                FileAutoDownloadSettingActivity.this.mArrList.set(1, Boolean.valueOf(FileAutoDownloadSettingActivity.this.mswitch_private_chat.isChecked()));
            }
        });
        this.fragmentView.findViewById(R.attr.rl_group_chat).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.FileAutoDownloadSettingActivity.5
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                FileAutoDownloadSettingActivity.this.mswitch_group_chat.setChecked(!FileAutoDownloadSettingActivity.this.mswitch_group_chat.isChecked(), true);
                FileAutoDownloadSettingActivity.this.mArrList.set(2, Boolean.valueOf(FileAutoDownloadSettingActivity.this.mswitch_group_chat.isChecked()));
            }
        });
        this.fragmentView.findViewById(R.attr.rl_channel).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.FileAutoDownloadSettingActivity.6
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                FileAutoDownloadSettingActivity.this.mswitch_channel.setChecked(!FileAutoDownloadSettingActivity.this.mswitch_channel.isChecked(), true);
                FileAutoDownloadSettingActivity.this.mArrList.set(3, Boolean.valueOf(FileAutoDownloadSettingActivity.this.mswitch_channel.isChecked()));
            }
        });
    }
}
