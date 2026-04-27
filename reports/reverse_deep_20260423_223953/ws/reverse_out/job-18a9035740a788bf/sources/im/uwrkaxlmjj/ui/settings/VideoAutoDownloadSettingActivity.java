package im.uwrkaxlmjj.ui.settings;

import android.animation.Animator;
import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
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
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class VideoAutoDownloadSettingActivity extends BaseFragment {
    private static final int SAVE_BUTTON = 1;
    private List<Boolean> mArrList;
    private AutoDownloadSettingActivity.activityButtonClickListener mListener;
    private RelativeLayout mRlPreload;
    private MrySwitch mScPreload;
    private long mSize;
    private TextView mTvPreload;
    private TextView mTvTip;
    private boolean mblnChecked;
    private MrySwitch mswitch_channel;
    private MrySwitch mswitch_contact;
    private MrySwitch mswitch_group_chat;
    private MrySwitch mswitch_private_chat;
    private final MaxFileSizeCell[] sizeCell = new MaxFileSizeCell[1];
    private FrameLayout mFrameLayout = null;

    public VideoAutoDownloadSettingActivity(List<Boolean> arrList, long lsize, boolean blnChecked, AutoDownloadSettingActivity.activityButtonClickListener listener) {
        this.mSize = 0L;
        this.mListener = null;
        this.mArrList = arrList;
        this.mSize = lsize;
        this.mblnChecked = blnChecked;
        this.mListener = listener;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setTitle(LocaleController.getString("AutoDownloadVideosOn", R.string.AutoDownloadVideosOn));
        if (AndroidUtilities.isTablet()) {
            this.actionBar.setOccupyStatusBar(false);
        }
        this.actionBar.setAllowOverlayTitle(true);
        ActionBarMenu menu = this.actionBar.createMenu();
        menu.addRightItemView(1, LocaleController.getString("Save", R.string.Save));
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_setting_auto_download_video, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initView(context);
        initListener();
        return this.fragmentView;
    }

    private void initView(Context context) {
        this.mScPreload = (MrySwitch) this.fragmentView.findViewById(R.attr.switch_preload);
        this.mTvTip = (TextView) this.fragmentView.findViewById(R.attr.tv_tip);
        this.mRlPreload = (RelativeLayout) this.fragmentView.findViewById(R.attr.rl_preload);
        this.mFrameLayout = (FrameLayout) this.fragmentView.findViewById(R.attr.fl_container);
        this.mTvPreload = (TextView) this.fragmentView.findViewById(R.attr.tv_preload);
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
        this.sizeCell[0] = new MaxFileSizeCell(getParentActivity()) { // from class: im.uwrkaxlmjj.ui.settings.VideoAutoDownloadSettingActivity.1
            @Override // im.uwrkaxlmjj.ui.cells.MaxFileSizeCell
            protected void didChangedSizeValue(int value) {
                VideoAutoDownloadSettingActivity.this.mTvTip.setText(LocaleController.formatString("AutoDownloadPreloadVideoInfo", R.string.AutoDownloadPreloadVideoInfo, AndroidUtilities.formatFileSize(value)));
                boolean enabled = value > 2097152;
                if (enabled != VideoAutoDownloadSettingActivity.this.mRlPreload.isEnabled()) {
                    VideoAutoDownloadSettingActivity.this.preLoadEnabled(enabled);
                }
            }
        };
        this.sizeCell[0].setSize(this.mSize);
        this.mFrameLayout.addView(this.sizeCell[0], LayoutHelper.createLinear(-1, 50));
        this.mFrameLayout.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.sizeCell[0].setText(LocaleController.getString("AutoDownloadMaxVideoSize", R.string.AutoDownloadMaxVideoSize));
        this.mScPreload.setChecked(this.mblnChecked, true);
        this.mTvTip.setText(LocaleController.formatString("AutoDownloadPreloadVideoInfo", R.string.AutoDownloadPreloadVideoInfo, AndroidUtilities.formatFileSize(this.mSize)));
        boolean hasAny = false;
        int b = 0;
        while (true) {
            if (b >= this.mArrList.size()) {
                break;
            }
            if (!this.mArrList.get(b).booleanValue()) {
                b++;
            } else {
                hasAny = true;
                break;
            }
        }
        if (!hasAny) {
            this.sizeCell[0].setEnabled(hasAny, null);
            preLoadEnabled(hasAny);
        }
        if (this.mSize <= 2097152) {
            preLoadEnabled(false);
        }
        this.fragmentView.findViewById(R.attr.rl_contact).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0, 0, Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_private_chat).setBackground(Theme.getSelectorDrawable(true));
        this.fragmentView.findViewById(R.attr.rl_group_chat).setBackground(Theme.getSelectorDrawable(true));
        this.fragmentView.findViewById(R.attr.rl_channel).setBackground(Theme.getRoundRectSelectorDrawable(0, 0, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_preload).setBackground(Theme.getRoundRectSelectorDrawable(0, 0, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
    }

    private void initListener() {
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.settings.VideoAutoDownloadSettingActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    VideoAutoDownloadSettingActivity.this.finishFragment();
                } else if (id == 1) {
                    if (VideoAutoDownloadSettingActivity.this.mListener != null) {
                        VideoAutoDownloadSettingActivity.this.mListener.onSaveBtnClick(VideoAutoDownloadSettingActivity.this.mArrList, VideoAutoDownloadSettingActivity.this.sizeCell[0].getSize(), VideoAutoDownloadSettingActivity.this.mScPreload.isChecked());
                    }
                    VideoAutoDownloadSettingActivity.this.finishFragment();
                }
            }
        });
        this.fragmentView.findViewById(R.attr.rl_contact).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.VideoAutoDownloadSettingActivity.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                VideoAutoDownloadSettingActivity.this.mswitch_contact.setChecked(!VideoAutoDownloadSettingActivity.this.mswitch_contact.isChecked(), true);
                VideoAutoDownloadSettingActivity.this.mArrList.set(0, Boolean.valueOf(VideoAutoDownloadSettingActivity.this.mswitch_contact.isChecked()));
                VideoAutoDownloadSettingActivity.this.processUpdate();
            }
        });
        this.fragmentView.findViewById(R.attr.rl_private_chat).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.VideoAutoDownloadSettingActivity.4
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                VideoAutoDownloadSettingActivity.this.mswitch_private_chat.setChecked(!VideoAutoDownloadSettingActivity.this.mswitch_private_chat.isChecked(), true);
                VideoAutoDownloadSettingActivity.this.mArrList.set(1, Boolean.valueOf(VideoAutoDownloadSettingActivity.this.mswitch_private_chat.isChecked()));
                VideoAutoDownloadSettingActivity.this.processUpdate();
            }
        });
        this.fragmentView.findViewById(R.attr.rl_group_chat).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.VideoAutoDownloadSettingActivity.5
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                VideoAutoDownloadSettingActivity.this.mswitch_group_chat.setChecked(!VideoAutoDownloadSettingActivity.this.mswitch_group_chat.isChecked(), true);
                VideoAutoDownloadSettingActivity.this.mArrList.set(2, Boolean.valueOf(VideoAutoDownloadSettingActivity.this.mswitch_group_chat.isChecked()));
                VideoAutoDownloadSettingActivity.this.processUpdate();
            }
        });
        this.fragmentView.findViewById(R.attr.rl_channel).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.VideoAutoDownloadSettingActivity.6
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                VideoAutoDownloadSettingActivity.this.mswitch_channel.setChecked(!VideoAutoDownloadSettingActivity.this.mswitch_channel.isChecked(), true);
                VideoAutoDownloadSettingActivity.this.mArrList.set(3, Boolean.valueOf(VideoAutoDownloadSettingActivity.this.mswitch_channel.isChecked()));
                VideoAutoDownloadSettingActivity.this.processUpdate();
            }
        });
        this.fragmentView.findViewById(R.attr.rl_preload).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.VideoAutoDownloadSettingActivity.7
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                VideoAutoDownloadSettingActivity.this.mScPreload.setChecked(!VideoAutoDownloadSettingActivity.this.mScPreload.isChecked(), true);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processUpdate() {
        boolean hasAny = false;
        int b = 0;
        while (true) {
            if (b >= this.mArrList.size()) {
                break;
            }
            if (!this.mArrList.get(b).booleanValue()) {
                b++;
            } else {
                hasAny = true;
                break;
            }
        }
        if (this.sizeCell[0].isEnabled() != hasAny) {
            ArrayList<Animator> animators = new ArrayList<>();
            this.sizeCell[0].setEnabled(hasAny, animators);
            if (this.sizeCell[0].getSize() > 2097152) {
                preLoadEnabled(hasAny);
            }
        }
    }

    public void preLoadEnabled(boolean value) {
        this.mTvPreload.setAlpha(value ? 1.0f : 0.5f);
        this.mScPreload.setAlpha(value ? 1.0f : 0.5f);
        this.fragmentView.findViewById(R.attr.rl_preload).setEnabled(value);
    }
}
