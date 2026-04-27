package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import androidx.appcompat.widget.Toolbar;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.bean.AvatarPhotoBean;
import com.bjz.comm.net.bean.FCEntitysRequest;
import com.bjz.comm.net.bean.FcIgnoreUserBean;
import com.bjz.comm.net.bean.FcLikeBean;
import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.bean.FcUserInfoBean;
import com.bjz.comm.net.bean.RequestReplyFcBean;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.bean.RespFcUserStatisticsBean;
import com.bjz.comm.net.bean.RespOthersFcListBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.presenter.FcPageOthersPresenter;
import com.bjz.comm.net.utils.HttpUtils;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.appbar.CollapsingToolbarLayout;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import com.scwang.smartrefresh.layout.api.RefreshLayout;
import com.scwang.smartrefresh.layout.constant.RefreshState;
import com.scwang.smartrefresh.layout.listener.OnRefreshLoadMoreListener;
import com.socks.library.KLog;
import im.uwrkaxlmjj.javaBean.fc.FcLocationInfoBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.utils.ShapeUtils;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.dialogs.FcDialog;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeItemReplyAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.UserFcListAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.decoration.SpacesItemDecoration;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.glide.GlideUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.VideoPlayerManager;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.state.ScreenViewState;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.AutoPlayTool;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.FcDialogUtil;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.StringUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.TimeUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcPageOthersActivity extends CommFcListActivity implements NotificationCenter.NotificationCenterDelegate, FcItemActionClickListener, BaseFcContract.IFcPageOthersView {
    private long accessHash;
    private AutoPlayTool autoPlayTool;
    private MryTextView btnFollow;
    private ImageView ivFcBg;
    private ImageView ivFcOperate;
    private BackupImageView ivUserAvatar;
    private UserFcListAdapter mAdapter;
    private FcPageOthersPresenter mPresenter;
    private SmartRefreshLayout mSmartRefreshLayout;
    private RespFcListBean replyItemModel;
    private RelativeLayout rlEmptyView;
    private RelativeLayout rlIgnoreView;
    private RecyclerView rvFcList;
    private MryTextView tvFansNum;
    private MryTextView tvFollowedUserNum;
    private MryTextView tvGender;
    private MryTextView tvLikeNum;
    private MryTextView tvPublishFcNum;
    private MryTextView tvUserName;
    private int userId;
    private String TAG = FcPageOthersActivity.class.getSimpleName();
    private int pageNo = 0;
    private int roundNum = 1;
    private int replyParentPosition = -1;
    private int replyChildPosition = -1;
    private ArrayList<RespFcListBean> mTempFcList = new ArrayList<>();
    RecyclerView.OnScrollListener rvScrollListener = new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageOthersActivity.8
        boolean isScroll = false;

        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
            super.onScrolled(recyclerView, dx, dy);
            if (FcPageOthersActivity.this.autoPlayTool != null && this.isScroll) {
                FcPageOthersActivity.this.autoPlayTool.onScrolledAndDeactivate();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
            super.onScrollStateChanged(recyclerView, newState);
            this.isScroll = newState != 0;
            if (newState == 0) {
                if (FcPageOthersActivity.this.mSmartRefreshLayout.getState() == RefreshState.None || FcPageOthersActivity.this.mSmartRefreshLayout.getState() == RefreshState.RefreshFinish) {
                    FcPageOthersActivity.this.isActivePlayer(recyclerView);
                }
            }
        }
    };
    private PhotoViewer.PhotoViewerProvider provider = new PhotoViewer.EmptyPhotoViewerProvider() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageOthersActivity.9
        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public PhotoViewer.PlaceProviderObject getPlaceForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index, boolean needPreview) {
            TLRPC.User user;
            if (fileLocation == null || FcPageOthersActivity.this.isFinishing()) {
                return null;
            }
            TLRPC.FileLocation photoBig = null;
            if (FcPageOthersActivity.this.userId != 0 && (user = MessagesController.getInstance(FcPageOthersActivity.this.currentAccount).getUser(Integer.valueOf(FcPageOthersActivity.this.userId))) != null && user.photo != null && user.photo.photo_big != null) {
                photoBig = user.photo.photo_big;
            }
            if (photoBig == null || photoBig.local_id != fileLocation.local_id || photoBig.volume_id != fileLocation.volume_id || photoBig.dc_id != fileLocation.dc_id) {
                return null;
            }
            int[] coords = new int[2];
            FcPageOthersActivity.this.ivUserAvatar.getLocationInWindow(coords);
            PhotoViewer.PlaceProviderObject object = new PhotoViewer.PlaceProviderObject();
            object.viewX = coords[0];
            object.viewY = coords[1];
            object.parentView = FcPageOthersActivity.this.ivUserAvatar;
            object.imageReceiver = FcPageOthersActivity.this.ivUserAvatar.getImageReceiver();
            if (FcPageOthersActivity.this.userId != 0) {
                object.dialogId = FcPageOthersActivity.this.userId;
            }
            object.thumb = object.imageReceiver.getBitmapSafe();
            object.size = -1;
            object.radius = FcPageOthersActivity.this.ivUserAvatar.getImageReceiver().getRoundRadius();
            object.scale = FcPageOthersActivity.this.ivUserAvatar.getScaleX();
            return object;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public void willHidePhotoViewer() {
            FcPageOthersActivity.this.ivUserAvatar.getImageReceiver().setVisible(true, true);
        }
    };

    public FcPageOthersActivity(FcUserInfoBean fcUserInfoBean) {
        this.userId = 0;
        if (fcUserInfoBean != null) {
            this.userId = fcUserInfoBean.getUserId();
            this.accessHash = fcUserInfoBean.getAccessHash();
        }
    }

    public FcPageOthersActivity(int userId) {
        this.userId = 0;
        this.userId = userId;
    }

    public FcPageOthersActivity(int userId, long accessHash) {
        this.userId = 0;
        this.userId = userId;
        this.accessHash = accessHash;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected int getLayoutRes() {
        return R.layout.activity_fc_page_others;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initView() {
        VideoPlayerManager.getInstance().setVolume(0);
        this.actionBar.setVisibility(8);
        this.mSmartRefreshLayout = (SmartRefreshLayout) this.fragmentView.findViewById(R.attr.smartRefreshLayout);
        final CollapsingToolbarLayout ctlTitle = (CollapsingToolbarLayout) this.fragmentView.findViewById(R.attr.ctl_title);
        AppBarLayout mAppbarLayout = (AppBarLayout) this.fragmentView.findViewById(R.attr.mAppbarLayout);
        Toolbar toolbar = (Toolbar) this.fragmentView.findViewById(R.attr.toolbar);
        ActionBar actionBar = this.actionBar;
        int actionBarHeight = ActionBar.getCurrentActionBarHeight() + AndroidUtilities.statusBarHeight;
        ViewGroup.LayoutParams layoutParams = toolbar.getLayoutParams();
        layoutParams.width = -1;
        layoutParams.height = actionBarHeight;
        toolbar.setLayoutParams(layoutParams);
        ctlTitle.setMinimumHeight(actionBarHeight);
        ctlTitle.setContentScrimColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.fragmentView.findViewById(R.attr.rl_header).setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        final ImageView icBack = (ImageView) this.fragmentView.findViewById(R.attr.ic_back);
        final MryTextView tvTitle = (MryTextView) this.fragmentView.findViewById(R.attr.tv_title);
        tvTitle.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.ivFcOperate = (ImageView) this.fragmentView.findViewById(R.attr.iv_fc_operate);
        this.ivFcBg = (ImageView) this.fragmentView.findViewById(R.attr.iv_fc_bg);
        BackupImageView backupImageView = (BackupImageView) this.fragmentView.findViewById(R.attr.iv_user_avatar);
        this.ivUserAvatar = backupImageView;
        backupImageView.setBackground(ShapeUtils.create(this.mContext.getResources().getColor(R.color.color_FFE8E8E8), AndroidUtilities.dp(8.0f)));
        this.ivUserAvatar.setRoundRadius(AndroidUtilities.dp(8.0f));
        this.tvUserName = (MryTextView) this.fragmentView.findViewById(R.attr.tv_user_name);
        this.tvGender = (MryTextView) this.fragmentView.findViewById(R.attr.tv_gender);
        this.btnFollow = (MryTextView) this.fragmentView.findViewById(R.attr.btn_follow);
        MryTextView btnChat = (MryTextView) this.fragmentView.findViewById(R.attr.btn_chat);
        this.tvPublishFcNum = (MryTextView) this.fragmentView.findViewById(R.attr.tv_publish_fc_num);
        this.tvFollowedUserNum = (MryTextView) this.fragmentView.findViewById(R.attr.tv_followed_user_num);
        this.tvLikeNum = (MryTextView) this.fragmentView.findViewById(R.attr.tv_like_num);
        this.tvFansNum = (MryTextView) this.fragmentView.findViewById(R.attr.tv_fans_num);
        this.tvPublishFcNum.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.tvFollowedUserNum.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.tvLikeNum.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.tvFansNum.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.rvFcList = (RecyclerView) this.fragmentView.findViewById(R.attr.rv_fc_list);
        this.rlEmptyView = (RelativeLayout) this.fragmentView.findViewById(R.attr.rl_empty);
        this.rlIgnoreView = (RelativeLayout) this.fragmentView.findViewById(R.attr.rl_ignore);
        final boolean isLight = Theme.getCurrentTheme().isLight();
        mAppbarLayout.addOnOffsetChangedListener(new AppBarLayout.OnOffsetChangedListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageOthersActivity.1
            @Override // com.google.android.material.appbar.AppBarLayout.OnOffsetChangedListener, com.google.android.material.appbar.AppBarLayout.BaseOnOffsetChangedListener
            public void onOffsetChanged(AppBarLayout appBarLayout, int verticalOffset) {
                int scrollDistance = Math.abs(verticalOffset);
                if (scrollDistance < ctlTitle.getScrimVisibleHeightTrigger()) {
                    icBack.setImageResource(R.id.ic_fc_back_white);
                    FcPageOthersActivity.this.ivFcOperate.setImageResource(R.id.ic_fc_user_operate_white);
                    tvTitle.setAlpha(0.0f);
                } else {
                    if (isLight) {
                        icBack.setImageResource(R.id.ic_fc_back_black);
                    } else {
                        icBack.setImageResource(R.id.ic_fc_back_white);
                    }
                    FcPageOthersActivity.this.ivFcOperate.setImageResource(R.id.ic_fc_user_operate_black);
                    tvTitle.setAlpha(1.0f);
                }
            }
        });
        icBack.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageOthersActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                FcPageOthersActivity.this.finishFragment();
            }
        });
        this.ivUserAvatar.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPageOthersActivity$6zW8ejv6RX19I5_XQH9FMO1CFk0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initView$0$FcPageOthersActivity(view);
            }
        });
        btnChat.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageOthersActivity.3
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (FcPageOthersActivity.this.userId > 0) {
                    Bundle args1 = new Bundle();
                    args1.putInt("user_id", FcPageOthersActivity.this.userId);
                    FcPageOthersActivity.this.presentFragment(new ChatActivity(args1));
                }
            }
        });
        this.btnFollow.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageOthersActivity.4
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (FcPageOthersActivity.this.userId > 0) {
                    if (FcPageOthersActivity.this.btnFollow.isSelected()) {
                        FcPageOthersActivity.this.doCancelFollowed(r0.userId);
                    } else {
                        FcPageOthersActivity.this.doFollow(r0.userId);
                    }
                }
            }
        });
        this.mSmartRefreshLayout.setOnRefreshLoadMoreListener(new OnRefreshLoadMoreListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageOthersActivity.5
            @Override // com.scwang.smartrefresh.layout.listener.OnRefreshListener
            public void onRefresh(RefreshLayout refreshLayout) {
                FcPageOthersActivity.this.loadFcBaseInfo();
                FcPageOthersActivity.this.pageNo = 0;
                FcPageOthersActivity.this.getFcPageList();
            }

            @Override // com.scwang.smartrefresh.layout.listener.OnLoadMoreListener
            public void onLoadMore(RefreshLayout refreshLayout) {
                FcPageOthersActivity.this.getFcPageList();
            }
        });
        this.mSmartRefreshLayout.setEnableLoadMore(false);
        this.layoutManager = new LinearLayoutManager(this.mContext, 1, false);
        this.rvFcList.setLayoutManager(this.layoutManager);
        SpacesItemDecoration decoration = new SpacesItemDecoration(AndroidUtilities.dp(7.0f));
        decoration.isShowTop(true);
        this.rvFcList.addItemDecoration(decoration);
        UserFcListAdapter userFcListAdapter = new UserFcListAdapter(new ArrayList(), getParentActivity(), getClassGuid(), this);
        this.mAdapter = userFcListAdapter;
        userFcListAdapter.setFooterCount(1);
        this.rvFcList.setAdapter(this.mAdapter);
        this.rvFcList.addOnScrollListener(this.rvScrollListener);
    }

    public /* synthetic */ void lambda$initView$0$FcPageOthersActivity(View v) {
        TLRPC.User user1;
        if (this.userId > 0 && (user1 = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.userId))) != null && user1.photo != null && user1.photo.photo_big != null) {
            PhotoViewer.getInstance().setParentActivity(getParentActivity());
            if (user1.photo.dc_id != 0) {
                user1.photo.photo_big.dc_id = user1.photo.dc_id;
            }
            PhotoViewer.getInstance().openPhoto(user1.photo.photo_big, this.provider);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        getParentActivity().getWindow().setSoftInputMode(16);
        VideoPlayerManager.getInstance().resume();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageOthersActivity.6
            @Override // java.lang.Runnable
            public void run() {
                if (FcPageOthersActivity.this.rvScrollListener != null) {
                    FcPageOthersActivity.this.rvScrollListener.onScrollStateChanged(FcPageOthersActivity.this.rvFcList, 0);
                }
            }
        }, 1000L);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        if (ScreenViewState.isFullScreen(VideoPlayerManager.getInstance().getmScreenState())) {
            VideoPlayerManager.getInstance().onBackPressed();
        }
        setStopPlayState();
        super.onPause();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity, im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.userFullInfoDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fcFollowStatusUpdate);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fcPermissionStatusUpdate);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fcLikeStatusUpdate);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fcReplyItem);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fcDeleteReplyItem);
        VideoPlayerManager.getInstance().release();
        FcPageOthersPresenter fcPageOthersPresenter = this.mPresenter;
        if (fcPageOthersPresenter != null) {
            fcPageOthersPresenter.unSubscribeTask();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initData() {
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.userFullInfoDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fcFollowStatusUpdate);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fcPermissionStatusUpdate);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fcLikeStatusUpdate);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fcReplyItem);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fcDeleteReplyItem);
        this.mPresenter = new FcPageOthersPresenter(this);
        loadUserInfo();
        loadFcBaseInfo();
        getFcPageList();
    }

    private void loadUserInfo() {
        TLRPC.User itemUser;
        if (this.userId > 0 && (itemUser = getAccountInstance().getMessagesController().getUser(Integer.valueOf(this.userId))) != null) {
            AvatarDrawable avatarDrawable = new AvatarDrawable(itemUser, true);
            this.ivUserAvatar.setImage(ImageLocation.getForUser(itemUser, false), "60_60", avatarDrawable, itemUser);
            this.tvUserName.setText(StringUtils.handleTextName(ContactsController.formatName(itemUser.first_name, itemUser.last_name), 12));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void loadFcBaseInfo() {
        int i = this.userId;
        if (i == -1) {
            return;
        }
        this.mPresenter.getActionCount(i);
        this.mPresenter.checkIsFollowed(this.userId);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageOthersView
    public void checkIsFollowedSucc(Boolean isFollowed) {
        if (isFollowed != null) {
            this.btnFollow.setSelected(isFollowed.booleanValue());
            this.btnFollow.setText(isFollowed.booleanValue() ? "已关注" : "关注");
        }
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageOthersView
    public void getActionCountSucc(RespFcUserStatisticsBean data) {
        if (data != null) {
            this.tvPublishFcNum.setText(Integer.toString(data.getForumCount()));
            this.tvFollowedUserNum.setText(Integer.toString(data.getFollowCount()));
            this.tvLikeNum.setText(Integer.toString(data.getThumbCount()));
            this.tvFansNum.setText(Integer.toString(data.getFansCount()));
            if (!TextUtils.isEmpty(data.getHomeBackground()) && this.ivFcBg != null) {
                GlideUtils.getInstance().load(HttpUtils.getInstance().getDownloadFileUrl() + data.getHomeBackground(), this.mContext, this.ivFcBg, R.drawable.shape_fc_default_pic_bg);
            }
            FcUserInfoBean fcUserInfoBean = data.getUser();
            if (fcUserInfoBean != null) {
                if (this.tvGender != null) {
                    if (fcUserInfoBean.getSex() != 0) {
                        this.tvGender.setSelected(fcUserInfoBean.getSex() == 1);
                        if (fcUserInfoBean.getBirthday() > 0) {
                            Date date = new Date(((long) fcUserInfoBean.getBirthday()) * 1000);
                            int ageByBirthday = TimeUtils.getAgeByBirthday(date);
                            this.tvGender.setText(ageByBirthday > 0 ? String.valueOf(ageByBirthday) : "");
                            this.tvGender.setCompoundDrawablePadding(ageByBirthday > 0 ? AndroidUtilities.dp(2.0f) : 0);
                        } else {
                            this.tvGender.setText("");
                            this.tvGender.setCompoundDrawablePadding(0);
                        }
                        this.tvGender.setVisibility(0);
                    } else {
                        this.tvGender.setVisibility(8);
                    }
                }
                AvatarPhotoBean avatarPhotoBean = fcUserInfoBean.getPhoto();
                if (avatarPhotoBean != null) {
                    int photoSize = avatarPhotoBean.getSmallPhotoSize();
                    int localId = avatarPhotoBean.getSmallLocalId();
                    long volumeId = avatarPhotoBean.getSmallVolumeId();
                    if (photoSize != 0 && volumeId != 0 && avatarPhotoBean.getAccess_hash() != 0) {
                        TLRPC.TL_inputPeerUser inputPeer = new TLRPC.TL_inputPeerUser();
                        inputPeer.user_id = fcUserInfoBean.getUserId();
                        inputPeer.access_hash = fcUserInfoBean.getAccessHash();
                        ImageLocation imageLocation = new ImageLocation();
                        imageLocation.dc_id = 2;
                        imageLocation.photoPeer = inputPeer;
                        imageLocation.location = new TLRPC.TL_fileLocationToBeDeprecated();
                        imageLocation.location.local_id = localId;
                        imageLocation.location.volume_id = volumeId;
                        AvatarDrawable drawable = new AvatarDrawable();
                        this.ivUserAvatar.setImage(imageLocation, "40_40", drawable, inputPeer);
                    }
                }
                this.tvUserName.setText(StringUtils.handleTextName(ContactsController.formatName(fcUserInfoBean.getFirstName(), fcUserInfoBean.getLastName()), 12));
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getFcPageList() {
        if (this.userId <= 0) {
            return;
        }
        if (this.pageNo == 0) {
            this.mTempFcList.clear();
            this.roundNum = 1;
        }
        long forumId = this.pageNo == 0 ? 0L : this.mAdapter.getEndListId();
        this.mPresenter.getFCList(10, forumId, this.userId, this.roundNum);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageOthersView
    public void getFCListSucc(String code, RespOthersFcListBean response) {
        this.mSmartRefreshLayout.finishRefresh();
        this.mSmartRefreshLayout.finishLoadMore();
        if (TextUtils.equals(code, "SUC_FORUM_OTHER_MAIN_IGNORE")) {
            refreshPageState(true);
        } else {
            formatFcListData(response);
        }
    }

    private void formatFcListData(RespOthersFcListBean response) {
        if (response != null) {
            ArrayList<RespFcListBean> forums = response.getForums();
            boolean finish = response.isFinish();
            if (forums != null && forums.size() > 0) {
                this.mTempFcList.addAll(forums);
                int adapterCount = 0;
                if (this.pageNo != 0) {
                    adapterCount = this.mAdapter.getItemCount() - this.mAdapter.getFooterSize();
                }
                int maxLoadSize = adapterCount + 10;
                if (this.mTempFcList.size() >= maxLoadSize) {
                    int startIndex = 0;
                    if (this.pageNo != 0) {
                        startIndex = adapterCount;
                    }
                    ArrayList<RespFcListBean> mLoadFcList = new ArrayList<>();
                    for (int i = startIndex; i < maxLoadSize; i++) {
                        mLoadFcList.add(this.mTempFcList.get(i));
                    }
                    setData(mLoadFcList);
                    return;
                }
                if (!finish) {
                    this.roundNum++;
                    getFcPageList();
                    return;
                }
                int startIndex2 = 0;
                if (this.pageNo != 0) {
                    startIndex2 = adapterCount;
                }
                ArrayList<RespFcListBean> mLoadFcList2 = new ArrayList<>();
                for (int i2 = startIndex2; i2 < this.mTempFcList.size(); i2++) {
                    mLoadFcList2.add(this.mTempFcList.get(i2));
                }
                setData(mLoadFcList2);
                return;
            }
            int startIndex3 = 0;
            int adapterCount2 = 0;
            if (this.pageNo != 0) {
                adapterCount2 = this.mAdapter.getItemCount() - this.mAdapter.getFooterSize();
            }
            if (this.pageNo != 0) {
                startIndex3 = adapterCount2;
            }
            ArrayList<RespFcListBean> mLoadFcList3 = new ArrayList<>();
            for (int i3 = startIndex3; i3 < this.mTempFcList.size(); i3++) {
                mLoadFcList3.add(this.mTempFcList.get(i3));
            }
            setData(mLoadFcList3);
            return;
        }
        setData(null);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageOthersView
    public void getFCListFailed(String msg) {
        this.mSmartRefreshLayout.finishRefresh();
        this.mSmartRefreshLayout.finishLoadMore();
        FcToastUtils.show((CharSequence) LocaleController.getString("friendscircle_home_request_fail", R.string.friendscircle_home_request_fail));
    }

    private void setData(ArrayList<RespFcListBean> mFclistBeanList) {
        if (this.pageNo == 0) {
            if (mFclistBeanList == null || mFclistBeanList.size() == 0) {
                this.mSmartRefreshLayout.setEnableLoadMore(false);
                this.mAdapter.refresh(new ArrayList());
            } else {
                if (mFclistBeanList.size() < 10) {
                    this.mSmartRefreshLayout.setEnableLoadMore(false);
                    mFclistBeanList.add(new RespFcListBean());
                } else {
                    this.mSmartRefreshLayout.setEnableLoadMore(true);
                }
                this.mAdapter.refresh(mFclistBeanList);
                this.pageNo++;
            }
            AutoPlayTool autoPlayTool = this.autoPlayTool;
            if (autoPlayTool != null) {
                autoPlayTool.onRefreshDeactivate();
            }
            refreshPageState(false);
            return;
        }
        if (mFclistBeanList == null || mFclistBeanList.size() < 10) {
            mFclistBeanList.add(new RespFcListBean());
            this.mSmartRefreshLayout.setEnableLoadMore(false);
        }
        this.mAdapter.loadMore(mFclistBeanList);
        refreshPageState(false);
        if (mFclistBeanList.size() > 0) {
            this.pageNo++;
        }
    }

    private void refreshPageState(boolean isShowIgnore) {
        if (isShowIgnore) {
            this.rlIgnoreView.setVisibility(0);
            this.rlEmptyView.setVisibility(8);
            this.rvFcList.setVisibility(8);
            return;
        }
        this.rlIgnoreView.setVisibility(8);
        UserFcListAdapter userFcListAdapter = this.mAdapter;
        if (userFcListAdapter != null && userFcListAdapter.getDataList().size() <= this.mAdapter.getHeaderFooterCount()) {
            this.rlEmptyView.setVisibility(0);
            this.rvFcList.setVisibility(8);
        } else {
            this.rlEmptyView.setVisibility(8);
            this.rvFcList.setVisibility(0);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        int i1;
        int childPosition;
        if (id == NotificationCenter.userFullInfoDidLoad) {
            if (args != null && args.length >= 2 && (args[1] instanceof TLRPC.UserFull)) {
                Integer uid = (Integer) args[0];
                if (uid.intValue() == this.userId) {
                    TLRPC.UserFull userInfo = (TLRPC.UserFull) args[1];
                    if (userInfo instanceof TLRPCContacts.CL_userFull_v1) {
                        setExtraUserInfoData((TLRPCContacts.CL_userFull_v1) userInfo);
                        return;
                    }
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.fcFollowStatusUpdate) {
            String tag = (String) args[0];
            if (!TextUtils.equals(this.TAG, tag)) {
                long createBy = ((Long) args[1]).longValue();
                boolean isFollow = ((Boolean) args[2]).booleanValue();
                int position = -1;
                UserFcListAdapter userFcListAdapter = this.mAdapter;
                if (userFcListAdapter != null) {
                    List<RespFcListBean> dataList = userFcListAdapter.getDataList();
                    int i = 0;
                    while (true) {
                        if (i >= dataList.size()) {
                            break;
                        }
                        RespFcListBean respFcListBean = dataList.get(i);
                        if (respFcListBean == null || respFcListBean.getCreateBy() != createBy) {
                            i++;
                        } else {
                            position = i;
                            break;
                        }
                    }
                }
                if (position != -1) {
                    doFollowAfterViewChange(position, isFollow);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.fcPermissionStatusUpdate) {
            String tag2 = (String) args[0];
            if (!TextUtils.equals(this.TAG, tag2)) {
                long forumId = ((Long) args[1]).longValue();
                int permission = ((Integer) args[2]).intValue();
                int position2 = -1;
                UserFcListAdapter userFcListAdapter2 = this.mAdapter;
                if (userFcListAdapter2 != null) {
                    List<RespFcListBean> dataList2 = userFcListAdapter2.getDataList();
                    int i2 = 0;
                    while (true) {
                        if (i2 >= dataList2.size()) {
                            break;
                        }
                        RespFcListBean respFcListBean2 = dataList2.get(i2);
                        if (respFcListBean2 == null || respFcListBean2.getForumID() != forumId) {
                            i2++;
                        } else {
                            position2 = i2;
                            break;
                        }
                    }
                }
                if (position2 != -1) {
                    doSetItemPermissionAfterViewChange(forumId, permission, position2);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.fcLikeStatusUpdate) {
            String tag3 = (String) args[0];
            if (!TextUtils.equals(this.TAG, tag3)) {
                FcLikeBean fcLikeBean = (FcLikeBean) args[1];
                boolean isLike = ((Boolean) args[2]).booleanValue();
                int position3 = -1;
                if (this.mAdapter != null && fcLikeBean != null && fcLikeBean.getCommentID() == 0) {
                    List<RespFcListBean> dataList3 = this.mAdapter.getDataList();
                    int i3 = 0;
                    while (true) {
                        if (i3 >= dataList3.size()) {
                            break;
                        }
                        RespFcListBean respFcListBean3 = dataList3.get(i3);
                        if (respFcListBean3 == null || respFcListBean3.getForumID() != fcLikeBean.getForumID()) {
                            i3++;
                        } else {
                            position3 = i3;
                            break;
                        }
                    }
                }
                if (position3 != -1) {
                    doLikeAfterViewChange(position3, isLike, fcLikeBean);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.fcReplyItem) {
            String tag4 = (String) args[0];
            if (!TextUtils.equals(this.TAG, tag4)) {
                FcReplyBean data = (FcReplyBean) args[1];
                int position4 = -1;
                UserFcListAdapter userFcListAdapter3 = this.mAdapter;
                if (userFcListAdapter3 != null && data != null) {
                    List<RespFcListBean> dataList4 = userFcListAdapter3.getDataList();
                    int i4 = 0;
                    while (true) {
                        if (i4 >= dataList4.size()) {
                            break;
                        }
                        RespFcListBean respFcListBean4 = dataList4.get(i4);
                        if (respFcListBean4 == null || respFcListBean4.getForumID() != data.getForumID()) {
                            i4++;
                        } else {
                            position4 = i4;
                            break;
                        }
                    }
                }
                if (position4 != -1) {
                    doReplySuccAfterViewChange(data, position4);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.fcDeleteReplyItem) {
            String tag5 = (String) args[0];
            if (!TextUtils.equals(this.TAG, tag5)) {
                long forumId2 = ((Long) args[1]).longValue();
                long commentId = ((Long) args[2]).longValue();
                int childPosition2 = -1;
                UserFcListAdapter userFcListAdapter4 = this.mAdapter;
                if (userFcListAdapter4 != null && forumId2 > 0 && commentId > 0) {
                    List<RespFcListBean> dataList5 = userFcListAdapter4.getDataList();
                    for (int i5 = 0; i5 < dataList5.size(); i5++) {
                        RespFcListBean respFcListBean5 = dataList5.get(i5);
                        if (respFcListBean5 != null && respFcListBean5.getForumID() == forumId2) {
                            int parentPosition = i5;
                            ArrayList<FcReplyBean> comments = respFcListBean5.getComments();
                            int i12 = 0;
                            while (true) {
                                if (i12 >= comments.size()) {
                                    break;
                                }
                                FcReplyBean replyBean = comments.get(i12);
                                if (replyBean == null || replyBean.getCommentID() != commentId) {
                                    i12++;
                                } else {
                                    childPosition2 = i12;
                                    break;
                                }
                            }
                            i1 = parentPosition;
                            childPosition = childPosition2;
                        }
                    }
                    i1 = -1;
                    childPosition = -1;
                } else {
                    i1 = -1;
                    childPosition = -1;
                }
                if (i1 != -1 && childPosition != -1) {
                    doDeleteReplySuccAfterViewChange(forumId2, commentId, i1, childPosition);
                }
            }
        }
    }

    private void setExtraUserInfoData(TLRPCContacts.CL_userFull_v1 userFullV1) {
        if (userFullV1 != null) {
            final TLRPCContacts.CL_userFull_v1_Bean userFullV1Bean = userFullV1.getExtendBean();
            if (userFullV1Bean != null) {
                if (userFullV1Bean.sex != 0) {
                    this.tvGender.setSelected(userFullV1Bean.sex == 1);
                    if (userFullV1Bean.birthday > 0) {
                        Date date = new Date(((long) userFullV1Bean.birthday) * 1000);
                        int ageByBirthday = TimeUtils.getAgeByBirthday(date);
                        this.tvGender.setText(ageByBirthday > 0 ? String.valueOf(ageByBirthday) : "");
                        this.tvGender.setCompoundDrawablePadding(ageByBirthday > 0 ? AndroidUtilities.dp(2.0f) : 0);
                    } else {
                        this.tvGender.setText("");
                        this.tvGender.setCompoundDrawablePadding(0);
                    }
                    this.tvGender.setVisibility(0);
                } else {
                    this.tvGender.setVisibility(8);
                }
            }
            TLRPC.User user = userFullV1.user;
            if (user != null) {
                MessagesController.getInstance(UserConfig.selectedAccount).putUser(user, false);
                AvatarDrawable avatarDrawable = new AvatarDrawable(user, true);
                this.ivUserAvatar.setImage(ImageLocation.getForUser(user, false), "60_60", avatarDrawable, user);
                this.tvUserName.setText(StringUtils.handleTextName(ContactsController.formatName(user.first_name, user.last_name), 12));
                if (user.mutual_contact || user.contact) {
                    this.ivFcOperate.setVisibility(0);
                    this.ivFcOperate.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageOthersActivity.7
                        @Override // android.view.View.OnClickListener
                        public void onClick(View v) {
                            FcPageOthersActivity.this.presentFragment(new FcSettingActivity(FcPageOthersActivity.this.userId, userFullV1Bean.sex));
                        }
                    });
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener
    public void onAction(View view, int index, final int position, Object object) {
        if (index == UserFcListAdapter.Index_click_avatar) {
            if (object instanceof RespFcListBean) {
                RespFcListBean model = (RespFcListBean) object;
                if (model.getCreateBy() == getUserConfig().getCurrentUser().id) {
                    onPresentFragment(new FcPageMineActivity());
                    return;
                } else {
                    onPresentFragment(new FcPageOthersActivity(model.getCreatorUser()));
                    return;
                }
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_follow) {
            if (object instanceof RespFcListBean) {
                doFollow(position, (RespFcListBean) object);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_pop_cancel_follow) {
            if (object instanceof RespFcListBean) {
                doCancelFollowed(position, (RespFcListBean) object);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_pop_public) {
            if (object instanceof RespFcListBean) {
                setFcItemPermission((RespFcListBean) object, 1, position);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_pop_private) {
            if (object instanceof RespFcListBean) {
                setFcItemPermission((RespFcListBean) object, 2, position);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_pop_delete) {
            if (object instanceof RespFcListBean) {
                final RespFcListBean model2 = (RespFcListBean) object;
                FcDialogUtil.chooseIsDeleteMineItemDialog(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPageOthersActivity$fSdUQ_VOaOuG43LHXgglvmLR07w
                    @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onAction$1$FcPageOthersActivity(position, model2, view2);
                    }
                }, null);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_pop_shield_item) {
            if (object instanceof RespFcListBean) {
                final RespFcListBean model3 = (RespFcListBean) object;
                FcDialogUtil.chooseIsSetOtherFcItemPrivacyDialog(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPageOthersActivity$H05NsxuniksoHS6IK_C6frtA0Dg
                    @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onAction$2$FcPageOthersActivity(position, model3, view2);
                    }
                }, null);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_pop_shield_user) {
            if (object instanceof RespFcListBean) {
                final RespFcListBean model4 = (RespFcListBean) object;
                FcDialogUtil.choosePrivacyAllFcDialog(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPageOthersActivity$v2GWFVoWvsakboBnvLZbntqaqDk
                    @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onAction$3$FcPageOthersActivity(model4, view2);
                    }
                }, null);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_pop_report) {
            if (object instanceof RespFcListBean) {
                presentFragment(new FcReportActivity(((RespFcListBean) object).getForumID()));
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_download_photo || index == UserFcListAdapter.Index_download_video) {
            if (object instanceof String) {
                String path = (String) object;
                downloadFileToLocal(path);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_like) {
            if (object instanceof RespFcListBean) {
                RespFcListBean model5 = (RespFcListBean) object;
                if (model5.isHasThumb()) {
                    doCancelLikeFc(model5.getForumID(), model5.getCreateBy(), -1L, -1L, position);
                    return;
                } else {
                    doLike(model5.getForumID(), model5.getCreateBy(), -1L, -1L, position);
                    return;
                }
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_reply) {
            if (object instanceof RespFcListBean) {
            }
        } else if (index == UserFcListAdapter.Index_click_location && (object instanceof RespFcListBean)) {
            RespFcListBean model6 = (RespFcListBean) object;
            if (!TextUtils.isEmpty(model6.getLocationName()) && model6.getLongitude() != FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE && model6.getLatitude() != FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                FcLocationInfoBean fcLocationInfoBean = new FcLocationInfoBean(model6.getLongitude(), model6.getLatitude(), model6.getLocationName(), model6.getLocationAddress(), model6.getLocationCity());
                FcLocationInfoActivity locationInfoActivity = new FcLocationInfoActivity(fcLocationInfoBean);
                presentFragment(locationInfoActivity);
            }
        }
    }

    public /* synthetic */ void lambda$onAction$1$FcPageOthersActivity(int position, RespFcListBean model, View dialog) {
        doDeleteItem(position, model);
    }

    public /* synthetic */ void lambda$onAction$2$FcPageOthersActivity(int position, RespFcListBean model, View dialog) {
        doIgnoreItem(position, model);
    }

    public /* synthetic */ void lambda$onAction$3$FcPageOthersActivity(RespFcListBean model, View dialog) {
        ArrayList<FcIgnoreUserBean> list = new ArrayList<>();
        list.add(new FcIgnoreUserBean(model.getCreateBy(), 2));
        doAddIgnoreUser(list);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener
    public void onReplyClick(View v, String receiver, RespFcListBean model, int itemPosition, int replyPosition, boolean isLongClick) {
        if (!isLongClick) {
            if (itemPosition < this.mAdapter.getItemCount()) {
                this.replyItemModel = this.mAdapter.get(itemPosition);
            }
            this.replyParentPosition = itemPosition;
            this.replyChildPosition = replyPosition;
            showReplyFcDialog(receiver, this.replyItemModel.getForumID(), model.getCreateBy(), false, this.replyChildPosition == -1, model.isRecommend(), model.getRequiredVipLevel());
            return;
        }
        showDeleteBottomSheet(model, itemPosition, replyPosition);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener
    public void onPresentFragment(BaseFragment baseFragment) {
        setStopPlayState();
        if (baseFragment != null) {
            presentFragment(baseFragment);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcDoReplyDialog.OnFcDoReplyListener
    public void onInputReplyContent(String content, ArrayList<FCEntitysRequest> atUserBeanList) {
        long supID;
        long supUser;
        long replayID;
        long replayUID;
        if (TextUtils.isEmpty(content)) {
            FcToastUtils.show((CharSequence) LocaleController.getString("fc_tips_input_empty_comment", R.string.fc_tips_input_empty_comment));
            return;
        }
        RespFcListBean respFcListBean = this.replyItemModel;
        if (respFcListBean == null) {
            return;
        }
        long forumID = respFcListBean.getForumID();
        long forumUser = this.replyItemModel.getCreateBy();
        if (this.replyChildPosition == -1) {
            supID = 0;
            supUser = 0;
            replayID = forumID;
            replayUID = forumUser;
        } else {
            ArrayList<FcReplyBean> comments = this.replyItemModel.getComments();
            if (comments != null && this.replyChildPosition < comments.size()) {
                FcReplyBean fcReplyBean = comments.get(this.replyChildPosition);
                if (fcReplyBean.getReplayID() == forumID) {
                    long replayID2 = fcReplyBean.getCommentID();
                    long replayUID2 = fcReplyBean.getCreateBy();
                    long supID2 = fcReplyBean.getCommentID();
                    long supUser2 = fcReplyBean.getCreateBy();
                    supID = supID2;
                    supUser = supUser2;
                    replayID = replayID2;
                    replayUID = replayUID2;
                } else {
                    long replayID3 = fcReplyBean.getCommentID();
                    long replayUID3 = fcReplyBean.getCreateBy();
                    long supID3 = fcReplyBean.getSupID();
                    long supUser3 = fcReplyBean.getSupUser();
                    supID = supID3;
                    supUser = supUser3;
                    replayID = replayID3;
                    replayUID = replayUID3;
                }
            } else {
                supID = 0;
                supUser = 0;
                replayID = 0;
                replayUID = 0;
            }
        }
        RequestReplyFcBean mRequestReplyFcBean = new RequestReplyFcBean(forumID, forumUser, replayID, replayUID, supID, supUser, content, this.replyItemModel.getRequiredVipLevel());
        doReplyFc(mRequestReplyFcBean, this.replyParentPosition);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    protected void doFollowAfterViewChange(int position, boolean isFollow) {
        this.btnFollow.setText(isFollow ? "已关注" : "关注");
        this.btnFollow.setSelected(isFollow);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    protected void doSetItemPermissionAfterViewChange(long forumId, int permission, int position) {
        this.mAdapter.get(position).setPermission(permission);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    protected void doLikeAfterViewChange(int position, boolean isLike, FcLikeBean data) {
        View viewByPosition = this.layoutManager.findViewByPosition(position);
        MryTextView btnLike = null;
        if (viewByPosition != null && (btnLike = (MryTextView) viewByPosition.findViewById(R.attr.btn_like)) != null) {
            btnLike.setClickable(true);
        }
        if (data != null) {
            KLog.d("------position" + position + "  " + isLike);
            RespFcListBean model = this.mAdapter.get(position);
            this.mAdapter.get(position).setHasThumb(isLike);
            if (isLike) {
                this.mAdapter.get(position).setThumbUp(model.getThumbUp() + 1);
            } else {
                this.mAdapter.get(position).setThumbUp(this.mAdapter.get(position).getThumbUp() - 1);
            }
            if (btnLike != null) {
                btnLike.setText(model.getThumbUp() > 0 ? String.valueOf(model.getThumbUp()) : "0");
                btnLike.setSelected(isLike);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    protected void doReplySuccAfterViewChange(FcReplyBean data, int replyParentPosition) {
        RespFcListBean respFcListBean = this.mAdapter.get(replyParentPosition);
        if (respFcListBean != null && data != null) {
            ArrayList<FcReplyBean> comments = respFcListBean.getComments();
            ArrayList<FcReplyBean> morelist = new ArrayList<>();
            morelist.add(data);
            if (comments == null || comments.size() == 0) {
                respFcListBean.setComments(morelist);
            } else {
                comments.addAll(morelist);
            }
            respFcListBean.setCommentCount(respFcListBean.getCommentCount() + 1);
            View viewByPosition = this.layoutManager.findViewByPosition(replyParentPosition);
            if (viewByPosition != null) {
                MryTextView btnReply = (MryTextView) viewByPosition.findViewById(R.attr.btn_reply);
                if (btnReply != null) {
                    btnReply.setText(respFcListBean.getCommentCount() > 0 ? String.valueOf(respFcListBean.getCommentCount()) : "0");
                }
                RecyclerView rvReply = (RecyclerView) viewByPosition.findViewById(R.attr.rv_fc_comm_reply);
                if (rvReply != null) {
                    FcHomeItemReplyAdapter adapter = (FcHomeItemReplyAdapter) rvReply.getAdapter();
                    if (adapter != null && adapter.getItemCount() > 0) {
                        adapter.loadMore(morelist);
                    } else {
                        this.mAdapter.notifyItemChanged(replyParentPosition);
                    }
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    public void doDeleteReplySuccAfterViewChange(long forumId, long commentId, int parentPosition, int childPosition) {
        View viewByPosition;
        FcHomeItemReplyAdapter adapter;
        RespFcListBean respFcListBean = this.mAdapter.get(parentPosition);
        if (respFcListBean != null && (viewByPosition = this.layoutManager.findViewByPosition(parentPosition)) != null) {
            RecyclerView rvReply = (RecyclerView) viewByPosition.findViewById(R.attr.rv_fc_comm_reply);
            if (rvReply != null && childPosition != -1 && (adapter = (FcHomeItemReplyAdapter) rvReply.getAdapter()) != null && adapter.getDataList() != null && childPosition < adapter.getDataList().size()) {
                FcReplyBean fcReplyBean = adapter.getDataList().get(childPosition);
                ArrayList<FcReplyBean> temp = new ArrayList<>(adapter.getDataList());
                Iterator<FcReplyBean> iterator = temp.iterator();
                while (iterator.hasNext()) {
                    FcReplyBean next = iterator.next();
                    if (next != null && (next.getCommentID() == fcReplyBean.getCommentID() || next.getSupID() == fcReplyBean.getCommentID())) {
                        iterator.remove();
                    }
                }
                adapter.refresh(temp);
                respFcListBean.setCommentCount(temp.size());
                respFcListBean.getComments().clear();
                respFcListBean.getComments().addAll(temp);
            }
            MryTextView btnReply = (MryTextView) viewByPosition.findViewById(R.attr.btn_reply);
            if (btnReply != null) {
                btnReply.setText(respFcListBean.getCommentCount() > 0 ? String.valueOf(respFcListBean.getCommentCount()) : "0");
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity, im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void onError(String msg) {
        FcToastUtils.show((CharSequence) (msg == null ? LocaleController.getString("friendscircle_home_request_fail", R.string.friendscircle_home_request_fail) : msg));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void isActivePlayer(RecyclerView recyclerView) {
        if (this.autoPlayTool == null) {
            this.autoPlayTool = new AutoPlayTool(80, 1);
        }
        if (recyclerView != null) {
            this.autoPlayTool.onActiveWhenNoScrolling(recyclerView);
        }
    }

    private void setStopPlayState() {
        AutoPlayTool autoPlayTool = this.autoPlayTool;
        if (autoPlayTool != null) {
            autoPlayTool.onDeactivate();
        }
    }
}
