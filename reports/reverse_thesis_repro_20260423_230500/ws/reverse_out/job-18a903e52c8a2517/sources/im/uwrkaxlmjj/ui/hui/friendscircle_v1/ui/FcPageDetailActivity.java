package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.text.TextUtils;
import android.view.View;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.bean.FCEntitysRequest;
import com.bjz.comm.net.bean.FcLikeBean;
import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.bean.FcUserInfoBean;
import com.bjz.comm.net.bean.RequestReplyFcBean;
import com.bjz.comm.net.bean.RespFcLikesBean;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.presenter.FcPageDetailPresenter;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import com.scwang.smartrefresh.layout.api.RefreshLayout;
import com.scwang.smartrefresh.layout.constant.RefreshState;
import com.scwang.smartrefresh.layout.listener.OnRefreshLoadMoreListener;
import com.socks.library.KLog;
import im.uwrkaxlmjj.javaBean.fc.FcLocationInfoBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.utils.ShapeUtils;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailLikedUserAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDialogChildReplyAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.VideoPlayerManager;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.state.ScreenViewState;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.AutoPlayTool;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.StringUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcChildReplyListDialog;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcPageDetailActivity extends CommFcListActivity implements FcItemActionClickListener, BaseFcContract.IFcPageDetailView, FcChildReplyListDialog.ChildReplyListListener {
    private AutoPlayTool autoPlayTool;
    private MryTextView btnReply;
    private int commentChildPosition;
    private FcReplyBean commentItemModel;
    private int commentPageNo;
    private int commentParentPosition;
    private int[] coord;
    private int[] coordedt;
    private long forumId;
    private boolean isShowAtUser;
    private boolean isShowReplyDialog;
    int likeUserPageNo;
    private FcDetailAdapter mAdapter;
    private FcDialogChildReplyAdapter mChildReplyListAdapter;
    private BaseFcContract.IFcPageDetailPresenter mPresenter;
    private RespFcListBean mRespFcDetailBean;
    private SmartRefreshLayout mSmartRefreshLayout;
    private int pageIndex;
    private int replyCommentPosition;
    private FcReplyBean replyItemModel;
    private FcChildReplyListDialog replyListDialog;
    private int replyPageNo;
    private int replyPosition;
    private RecyclerView rvFcList;
    RecyclerView.OnScrollListener rvScrollListener;
    private long userId;

    public FcPageDetailActivity(long forumId) {
        this.coord = new int[2];
        this.coordedt = new int[2];
        this.commentPageNo = 0;
        this.commentParentPosition = -1;
        this.commentChildPosition = -1;
        this.isShowReplyDialog = false;
        this.pageIndex = 2;
        this.isShowAtUser = false;
        this.likeUserPageNo = 0;
        this.replyPageNo = 0;
        this.replyCommentPosition = -1;
        this.replyPosition = -1;
        this.rvScrollListener = new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageDetailActivity.9
            boolean isScroll = false;

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                super.onScrolled(recyclerView, dx, dy);
                if (FcPageDetailActivity.this.autoPlayTool != null && this.isScroll) {
                    FcPageDetailActivity.this.autoPlayTool.onScrolledAndDeactivate();
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                super.onScrollStateChanged(recyclerView, newState);
                this.isScroll = newState != 0;
                if (newState == 0) {
                    if (FcPageDetailActivity.this.mSmartRefreshLayout.getState() == RefreshState.None || FcPageDetailActivity.this.mSmartRefreshLayout.getState() == RefreshState.RefreshFinish) {
                        FcPageDetailActivity.this.isActivePlayer(recyclerView);
                    }
                }
            }
        };
        this.forumId = forumId;
    }

    public FcPageDetailActivity(RespFcListBean mRespFcDetailBean, boolean isShowReplyDialog) {
        this.coord = new int[2];
        this.coordedt = new int[2];
        this.commentPageNo = 0;
        this.commentParentPosition = -1;
        this.commentChildPosition = -1;
        this.isShowReplyDialog = false;
        this.pageIndex = 2;
        this.isShowAtUser = false;
        this.likeUserPageNo = 0;
        this.replyPageNo = 0;
        this.replyCommentPosition = -1;
        this.replyPosition = -1;
        this.rvScrollListener = new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageDetailActivity.9
            boolean isScroll = false;

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                super.onScrolled(recyclerView, dx, dy);
                if (FcPageDetailActivity.this.autoPlayTool != null && this.isScroll) {
                    FcPageDetailActivity.this.autoPlayTool.onScrolledAndDeactivate();
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                super.onScrollStateChanged(recyclerView, newState);
                this.isScroll = newState != 0;
                if (newState == 0) {
                    if (FcPageDetailActivity.this.mSmartRefreshLayout.getState() == RefreshState.None || FcPageDetailActivity.this.mSmartRefreshLayout.getState() == RefreshState.RefreshFinish) {
                        FcPageDetailActivity.this.isActivePlayer(recyclerView);
                    }
                }
            }
        };
        this.mRespFcDetailBean = mRespFcDetailBean;
        if (mRespFcDetailBean != null) {
            this.forumId = mRespFcDetailBean.getForumID();
            this.userId = mRespFcDetailBean.getCreateBy();
        }
        this.isShowReplyDialog = isShowReplyDialog;
        KLog.d("-----mResFcDetailBean" + mRespFcDetailBean.toString());
    }

    public FcPageDetailActivity(RespFcListBean mRespFcDetailBean, int pageIndex, boolean isShowReplyDialog) {
        this.coord = new int[2];
        this.coordedt = new int[2];
        this.commentPageNo = 0;
        this.commentParentPosition = -1;
        this.commentChildPosition = -1;
        this.isShowReplyDialog = false;
        this.pageIndex = 2;
        this.isShowAtUser = false;
        this.likeUserPageNo = 0;
        this.replyPageNo = 0;
        this.replyCommentPosition = -1;
        this.replyPosition = -1;
        this.rvScrollListener = new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageDetailActivity.9
            boolean isScroll = false;

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                super.onScrolled(recyclerView, dx, dy);
                if (FcPageDetailActivity.this.autoPlayTool != null && this.isScroll) {
                    FcPageDetailActivity.this.autoPlayTool.onScrolledAndDeactivate();
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                super.onScrollStateChanged(recyclerView, newState);
                this.isScroll = newState != 0;
                if (newState == 0) {
                    if (FcPageDetailActivity.this.mSmartRefreshLayout.getState() == RefreshState.None || FcPageDetailActivity.this.mSmartRefreshLayout.getState() == RefreshState.RefreshFinish) {
                        FcPageDetailActivity.this.isActivePlayer(recyclerView);
                    }
                }
            }
        };
        this.mRespFcDetailBean = mRespFcDetailBean;
        this.pageIndex = pageIndex;
        this.isShowAtUser = pageIndex == 1;
        if (mRespFcDetailBean != null) {
            this.forumId = mRespFcDetailBean.getForumID();
            this.userId = mRespFcDetailBean.getCreateBy();
        }
        this.isShowReplyDialog = isShowReplyDialog;
        KLog.d("-----mResFcDetailBean" + mRespFcDetailBean.toString());
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected int getLayoutRes() {
        return R.layout.activity_fc_page_detail;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initView() {
        initActionBar(LocaleController.getString("friends_circle_detail", R.string.friends_circle_detail));
        this.actionBar.setCastShadows(false);
        View view = new View(getParentActivity());
        view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.actionBar.addView(view, LayoutHelper.createFrame(-1.0f, 0.5f, 80));
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        if (getParentActivity() != null) {
            getParentActivity().getWindow().setSoftInputMode(16);
        }
        VideoPlayerManager.getInstance().setVolume(0);
        this.mSmartRefreshLayout = (SmartRefreshLayout) this.fragmentView.findViewById(R.attr.smartRefreshLayout);
        this.rvFcList = (RecyclerView) this.fragmentView.findViewById(R.attr.rv_fc_list);
        MryTextView mryTextView = (MryTextView) this.fragmentView.findViewById(R.attr.btn_reply);
        this.btnReply = mryTextView;
        mryTextView.setBackground(ShapeUtils.createStrokeAndFill(this.mContext.getResources().getColor(R.color.color_FFD8D8D8), AndroidUtilities.dp(1.0f), AndroidUtilities.dp(20.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.mSmartRefreshLayout.setOnRefreshLoadMoreListener(new OnRefreshLoadMoreListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageDetailActivity.1
            @Override // com.scwang.smartrefresh.layout.listener.OnRefreshListener
            public void onRefresh(RefreshLayout refreshLayout) {
                FcPageDetailActivity.this.getDetail();
            }

            @Override // com.scwang.smartrefresh.layout.listener.OnLoadMoreListener
            public void onLoadMore(RefreshLayout refreshLayout) {
                FcPageDetailActivity.this.getMoreComments();
            }
        });
        this.btnReply.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageDetailActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                FcPageDetailActivity.this.showReplyFcDialog();
            }
        });
        this.layoutManager = new LinearLayoutManager(this.mContext, 1, false);
        this.rvFcList.setLayoutManager(this.layoutManager);
        FcDetailAdapter fcDetailAdapter = new FcDetailAdapter(new ArrayList(), getParentActivity(), getClassGuid(), this);
        this.mAdapter = fcDetailAdapter;
        this.rvFcList.setAdapter(fcDetailAdapter);
        this.rvFcList.addOnScrollListener(this.rvScrollListener);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showReplyFcDialog() {
        RespFcListBean respFcListBean = this.mRespFcDetailBean;
        if (respFcListBean != null) {
            FcUserInfoBean creatorUser = respFcListBean.getCreatorUser();
            String forumUserName = "";
            if (creatorUser != null) {
                forumUserName = StringUtils.handleTextName(ContactsController.formatName(creatorUser.getFirstName(), creatorUser.getLastName()), 12);
            }
            super.showReplyFcDialog(forumUserName, this.mRespFcDetailBean.getForumID(), this.mRespFcDetailBean.getCreateBy(), this.isShowAtUser, true, this.mRespFcDetailBean.isRecommend(), this.mRespFcDetailBean.getRequiredVipLevel());
            this.commentParentPosition = 0;
            this.commentChildPosition = -1;
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initData() {
        FcDetailAdapter fcDetailAdapter;
        this.mPresenter = new FcPageDetailPresenter(this);
        RespFcListBean respFcListBean = this.mRespFcDetailBean;
        if (respFcListBean != null && (fcDetailAdapter = this.mAdapter) != null) {
            fcDetailAdapter.setFcContentData(respFcListBean);
            loadCommentData(this.mRespFcDetailBean.getComments());
        }
        getDetail();
        if (this.isShowReplyDialog && this.mRespFcDetailBean != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageDetailActivity.3
                @Override // java.lang.Runnable
                public void run() {
                    FcPageDetailActivity.this.showReplyFcDialog();
                }
            }, 500L);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        VideoPlayerManager.getInstance().resume();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageDetailActivity.4
            @Override // java.lang.Runnable
            public void run() {
                if (FcPageDetailActivity.this.rvScrollListener != null) {
                    FcPageDetailActivity.this.rvScrollListener.onScrollStateChanged(FcPageDetailActivity.this.rvFcList, 0);
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
        VideoPlayerManager.getInstance().release();
        BaseFcContract.IFcPageDetailPresenter iFcPageDetailPresenter = this.mPresenter;
        if (iFcPageDetailPresenter != null) {
            iFcPageDetailPresenter.unSubscribeTask();
        }
        dismissFcDoReplyDialog();
    }

    public void getDetail() {
        long j = this.forumId;
        if (j == 0) {
            return;
        }
        this.mPresenter.getDetail(j, this.userId);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailView
    public void getDetailSucc(RespFcListBean data) {
        View viewByPosition;
        this.mSmartRefreshLayout.finishRefresh();
        this.mSmartRefreshLayout.finishLoadMore();
        if (data != null) {
            this.isShowAtUser = this.pageIndex != 2 && data.isRecommend();
            RespFcListBean respFcListBean = this.mRespFcDetailBean;
            if (respFcListBean != null && respFcListBean.getCreatorUser() != null && (!TextUtils.isEmpty(this.mRespFcDetailBean.getContent()) || this.mRespFcDetailBean.getMedias() != null)) {
                this.mRespFcDetailBean = data;
                KLog.d("---------commentList.size()" + this.mRespFcDetailBean.getComments().size());
                this.mAdapter.setFcContentData(this.mRespFcDetailBean);
                boolean hasThumb = this.mRespFcDetailBean.isHasThumb();
                int thumbUp = this.mRespFcDetailBean.getThumbUp();
                int commentCount = this.mRespFcDetailBean.getCommentCount();
                if (this.layoutManager != null && this.mAdapter.getItemCount() > 0 && (viewByPosition = this.layoutManager.findViewByPosition(0)) != null) {
                    MryTextView btnLike = (MryTextView) viewByPosition.findViewById(R.attr.btn_like);
                    if (btnLike != null) {
                        btnLike.setClickable(true);
                        btnLike.setText(thumbUp > 0 ? String.valueOf(thumbUp) : "0");
                        btnLike.setSelected(hasThumb);
                    }
                    MryTextView btnReply = (MryTextView) viewByPosition.findViewById(R.attr.btn_reply);
                    if (btnReply != null) {
                        btnReply.setText(commentCount > 0 ? String.valueOf(commentCount) : "0");
                    }
                }
            } else {
                this.mRespFcDetailBean = data;
                KLog.d("---------commentList.size()" + this.mRespFcDetailBean.getComments().size());
                this.mAdapter.setFcContentData(this.mRespFcDetailBean);
                loadCommentData(this.mRespFcDetailBean.getComments());
            }
            this.commentPageNo = 0;
            getMoreComments();
            this.likeUserPageNo = 0;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageDetailActivity.5
                @Override // java.lang.Runnable
                public void run() {
                    FcPageDetailActivity.this.getLikeUserList();
                }
            }, 800L);
            return;
        }
        FcToastUtils.show((CharSequence) LocaleController.getString("CFGF1", R.string.CFGF1));
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageDetailActivity.6
            @Override // java.lang.Runnable
            public void run() {
                FcPageDetailActivity.this.finishFragment(true);
            }
        }, 1000L);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailView
    public void getDetailFailed(String msg) {
        this.mSmartRefreshLayout.finishRefresh();
        this.mSmartRefreshLayout.finishLoadMore();
        FcToastUtils.show((CharSequence) LocaleController.getString("CFGF1", R.string.CFGF1));
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageDetailActivity.7
            @Override // java.lang.Runnable
            public void run() {
                FcPageDetailActivity.this.finishFragment(true);
            }
        }, 1000L);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getMoreComments() {
        RespFcListBean respFcListBean = this.mRespFcDetailBean;
        if (respFcListBean == null || respFcListBean.getForumID() == 0) {
            return;
        }
        long commentId = 0;
        long forumUserId = 0;
        FcReplyBean fcReplyBean = this.commentPageNo == 0 ? null : this.mAdapter.getEndListId();
        if (fcReplyBean != null) {
            commentId = fcReplyBean.getCommentID();
            forumUserId = fcReplyBean.getCreateBy();
        }
        this.mPresenter.getComments(this.mRespFcDetailBean.getForumID(), commentId, forumUserId, 20);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailView
    public void getCommentsSucc(ArrayList<FcReplyBean> data) {
        this.mSmartRefreshLayout.finishRefresh();
        this.mSmartRefreshLayout.finishLoadMore();
        if (data != null) {
            loadCommentData(data);
            this.commentPageNo++;
        }
    }

    private void loadCommentData(ArrayList<FcReplyBean> data) {
        if (this.commentPageNo == 0) {
            if (data == null || data.size() == 0) {
                this.mSmartRefreshLayout.setEnableLoadMore(false);
                ArrayList<FcReplyBean> temp = new ArrayList<>();
                temp.add(new FcReplyBean());
                if (data.size() < 20) {
                    temp.add(new FcReplyBean());
                }
                this.mAdapter.refresh(temp);
                return;
            }
            if (data.size() < 20) {
                this.mSmartRefreshLayout.setEnableLoadMore(false);
            } else {
                this.mSmartRefreshLayout.setEnableLoadMore(true);
            }
            ArrayList<FcReplyBean> temp2 = new ArrayList<>();
            temp2.add(new FcReplyBean());
            temp2.addAll(data);
            if (data.size() < 20) {
                temp2.add(new FcReplyBean());
            }
            this.mAdapter.refresh(temp2);
            return;
        }
        if (data == null || data.size() < 20) {
            data.add(new FcReplyBean());
            this.mSmartRefreshLayout.setEnableLoadMore(false);
        }
        this.mAdapter.loadMore(data);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailView
    public void getCommentsFailed(String msg) {
        this.mSmartRefreshLayout.finishLoadMore();
        this.mSmartRefreshLayout.setEnableLoadMore(false);
        FcToastUtils.show(R.string.friendscircle_home_request_fail);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getLikeUserList() {
        List<FcLikeBean> dataList;
        FcLikeBean fcLikeBean;
        RespFcListBean respFcListBean = this.mRespFcDetailBean;
        if (respFcListBean != null && respFcListBean.getThumbUp() > 0) {
            long thumbId = 0;
            int limit = 8;
            if (this.likeUserPageNo != 0) {
                limit = 32;
                FcDetailLikedUserAdapter fcLikedUserAdapter = this.mAdapter.getFcLikedUserAdapter();
                if (fcLikedUserAdapter != null && (dataList = fcLikedUserAdapter.getDataList()) != null && dataList.size() > 0 && (fcLikeBean = dataList.get(dataList.size() - 1)) != null) {
                    thumbId = fcLikeBean.getThumbID();
                }
            }
            this.mPresenter.getLikeUserList(this.mRespFcDetailBean.getForumID(), thumbId, limit);
        }
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailView
    public void getLikeUserListSucc(RespFcLikesBean data) {
        if (data != null && data.getThumbs() != null && data.getUserInfo() != null && data.getThumbs().size() > 0 && data.getUserInfo().size() >= data.getThumbs().size()) {
            ArrayList<FcLikeBean> tempList = new ArrayList<>();
            Iterator<FcLikeBean> thumbsIterator = data.getThumbs().iterator();
            while (thumbsIterator.hasNext()) {
                FcLikeBean thumbNext = thumbsIterator.next();
                Iterator<FcUserInfoBean> it = data.getUserInfo().iterator();
                while (true) {
                    if (it.hasNext()) {
                        FcUserInfoBean userInfoNext = it.next();
                        if (thumbNext.getCreateBy() == userInfoNext.getUserId()) {
                            thumbNext.setCreator(userInfoNext);
                            tempList.add(thumbNext);
                            thumbsIterator.remove();
                            break;
                        }
                    }
                }
            }
            this.mAdapter.setFcLikeBeans(this.likeUserPageNo, tempList);
            this.likeUserPageNo++;
        }
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailView
    public void getLikeUserListFiled(String msg) {
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcChildReplyListDialog.ChildReplyListListener
    public void onReplyRefreshData() {
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcChildReplyListDialog.ChildReplyListListener
    public void onReplyLoadMoreData(FcReplyBean parentFcReplyBean, int position) {
        if (parentFcReplyBean != null && position > 0) {
            getMoreReplyList(parentFcReplyBean, position);
        }
    }

    public void getMoreReplyList(FcReplyBean parentFcReplyBean, int position) {
        RespFcListBean respFcListBean = this.mRespFcDetailBean;
        if (respFcListBean != null) {
            if (respFcListBean.getForumID() == 0) {
                return;
            }
            long commentId = this.replyPageNo != 0 ? this.mChildReplyListAdapter.getEndListId() : 0L;
            this.mPresenter.getReplyList(parentFcReplyBean, position, commentId, 20);
        }
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailView
    public void getReplyListSucc(FcReplyBean parentFcReplyBean, int parentFcReplyPosition, ArrayList<FcReplyBean> data) {
        loadReplyData(parentFcReplyBean, parentFcReplyPosition, data);
        this.replyPageNo++;
    }

    private void loadReplyData(FcReplyBean parentFcReplyBean, int parentFcReplyPosition, ArrayList<FcReplyBean> data) {
        if (this.replyListDialog == null) {
            FcChildReplyListDialog fcChildReplyListDialog = new FcChildReplyListDialog(getParentActivity());
            this.replyListDialog = fcChildReplyListDialog;
            fcChildReplyListDialog.setListener(this);
            this.mChildReplyListAdapter = this.replyListDialog.getChildReplyListAdapter();
        }
        if (this.replyPageNo == 0) {
            this.replyListDialog.setParentFcReplyData(parentFcReplyBean, parentFcReplyPosition);
        }
        this.replyListDialog.loadData(data, this.replyPageNo);
        FcChildReplyListDialog fcChildReplyListDialog2 = this.replyListDialog;
        if (fcChildReplyListDialog2 != null && !fcChildReplyListDialog2.isShowing()) {
            this.replyListDialog.show();
        }
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailView
    public void getReplyListFailed(FcReplyBean parentFcReplyBean, int parentFcReplyPosition, String msg) {
        if (this.replyPageNo == 0 && parentFcReplyBean != null) {
            loadReplyData(parentFcReplyBean, parentFcReplyPosition, parentFcReplyBean.getSubComment());
        } else {
            loadReplyData(parentFcReplyBean, parentFcReplyPosition, null);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener
    public void onAction(View view, int index, int position, Object object) {
        if (index == FcDetailAdapter.Index_click_avatar) {
            long userId = 0;
            FcUserInfoBean fcUserInfoBean = null;
            if (object instanceof RespFcListBean) {
                RespFcListBean model = (RespFcListBean) object;
                userId = model.getCreateBy();
                fcUserInfoBean = model.getCreatorUser();
            } else if (object instanceof FcLikeBean) {
                FcLikeBean model2 = (FcLikeBean) object;
                userId = model2.getCreateBy();
                fcUserInfoBean = model2.getCreator();
            } else if (object instanceof FcUserInfoBean) {
                fcUserInfoBean = (FcUserInfoBean) object;
                userId = fcUserInfoBean.getUserId();
            }
            if (userId != 0) {
                if (userId == getUserConfig().getCurrentUser().id) {
                    presentFragment(new FcPageMineActivity());
                } else if (fcUserInfoBean != null) {
                    presentFragment(new FcPageOthersActivity(fcUserInfoBean));
                }
            }
            return;
        }
        if (index == FcDetailAdapter.Index_download_photo || index == FcDetailAdapter.Index_download_video) {
            if (object instanceof String) {
                String path = (String) object;
                downloadFileToLocal(path);
                return;
            }
            return;
        }
        if (index == FcDetailAdapter.Index_click_forum_like) {
            if (object instanceof RespFcListBean) {
                RespFcListBean model3 = (RespFcListBean) object;
                if (model3.isHasThumb()) {
                    doCancelLikeFc(model3.getForumID(), model3.getCreateBy(), -1L, -1L, position);
                } else {
                    doLike(model3.getForumID(), model3.getCreateBy(), -1L, -1L, position);
                }
                return;
            }
            return;
        }
        if (index == FcDetailAdapter.Index_click_comment_like) {
            if (object instanceof FcReplyBean) {
                FcReplyBean model4 = (FcReplyBean) object;
                if (!model4.isHasThumb()) {
                    doLike(model4.getForumID(), this.mRespFcDetailBean.getCreateBy(), model4.getCommentID(), model4.getForumID(), position);
                } else {
                    doCancelLikeFc(model4.getForumID(), model4.getForumUser(), model4.getCommentID(), model4.getCreateBy(), position);
                }
                return;
            }
            return;
        }
        if (index == FcDetailAdapter.Index_click_comment) {
            showReplyFcDialog();
            return;
        }
        if (index == FcDetailAdapter.Index_click_more_reply) {
            if (object instanceof FcReplyBean) {
                this.replyPageNo = 0;
                getMoreReplyList((FcReplyBean) object, position);
                return;
            }
            return;
        }
        if (index == FcDetailAdapter.Index_click_location) {
            if (object instanceof RespFcListBean) {
                RespFcListBean model5 = (RespFcListBean) object;
                if (!TextUtils.isEmpty(model5.getLocationName()) && model5.getLongitude() != FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE && model5.getLatitude() != FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                    FcLocationInfoBean fcLocationInfoBean = new FcLocationInfoBean(model5.getLongitude(), model5.getLatitude(), model5.getLocationName(), model5.getLocationAddress(), model5.getLocationCity());
                    FcLocationInfoActivity locationInfoActivity = new FcLocationInfoActivity(fcLocationInfoBean);
                    presentFragment(locationInfoActivity);
                    return;
                }
                return;
            }
            return;
        }
        if (index == FcDetailAdapter.Index_click_load_more_like && (object instanceof FcLikeBean)) {
            getLikeUserList();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener
    public void onPresentFragment(BaseFragment baseFragment) {
        setStopPlayState();
        if (baseFragment != null) {
            presentFragment(baseFragment);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener
    public void onReplyClick(View v, String receiver, RespFcListBean model, int itemPosition, int replyPosition, boolean isLongClick) {
        FcReplyBean fcReplyBean;
        FcReplyBean deleteReplyBean;
        if (isLongClick) {
            if (itemPosition < this.mAdapter.getItemCount() && this.mAdapter.get(itemPosition) != null && (fcReplyBean = this.mAdapter.get(itemPosition)) != null) {
                if (replyPosition != -1 && fcReplyBean.getSubComment() != null && replyPosition < fcReplyBean.getSubComment().size()) {
                    deleteReplyBean = fcReplyBean.getSubComment().get(replyPosition);
                } else {
                    deleteReplyBean = fcReplyBean;
                }
                showDeleteBottomSheet(deleteReplyBean, itemPosition, replyPosition);
                return;
            }
            return;
        }
        if (itemPosition < this.mAdapter.getItemCount()) {
            if (replyPosition == -1) {
                this.commentItemModel = this.mAdapter.get(itemPosition);
            } else {
                FcReplyBean fcReplyBean2 = this.mAdapter.get(itemPosition);
                if (fcReplyBean2 != null && fcReplyBean2.getSubComment() != null && replyPosition < fcReplyBean2.getSubComment().size()) {
                    this.commentItemModel = fcReplyBean2.getSubComment().get(replyPosition);
                }
            }
        }
        this.commentParentPosition = itemPosition;
        this.commentChildPosition = replyPosition;
        RespFcListBean respFcListBean = this.mRespFcDetailBean;
        if (respFcListBean != null) {
            showReplyFcDialog(receiver, respFcListBean.getForumID(), this.mRespFcDetailBean.getCreateBy(), this.isShowAtUser, false, this.mRespFcDetailBean.isRecommend(), this.mRespFcDetailBean.getRequiredVipLevel());
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcDoReplyDialog.OnFcDoReplyListener
    public void onInputReplyContent(String content, ArrayList<FCEntitysRequest> atUserBeanList) {
        long replayID;
        long replayUID;
        long supID;
        long supUser;
        long replayID2;
        long replayUID2;
        long supID2;
        long supUser2;
        if (TextUtils.isEmpty(content)) {
            FcToastUtils.show((CharSequence) LocaleController.getString("fc_tips_input_empty_comment", R.string.fc_tips_input_empty_comment));
            return;
        }
        FcChildReplyListDialog fcChildReplyListDialog = this.replyListDialog;
        if (fcChildReplyListDialog != null && fcChildReplyListDialog.isShowing()) {
            FcReplyBean fcReplyBean = this.replyItemModel;
            if (fcReplyBean == null) {
                return;
            }
            long forumID = fcReplyBean.getForumID();
            long forumUser = this.replyItemModel.getForumUser();
            if (this.replyItemModel.getReplayID() == forumID) {
                long replayID3 = this.replyItemModel.getCommentID();
                long replayUID3 = this.replyItemModel.getCreateBy();
                long supID3 = this.replyItemModel.getCommentID();
                long supUser3 = this.replyItemModel.getCreateBy();
                replayID2 = replayID3;
                replayUID2 = replayUID3;
                supID2 = supID3;
                supUser2 = supUser3;
            } else {
                long replayID4 = this.replyItemModel.getCommentID();
                long replayUID4 = this.replyItemModel.getCreateBy();
                long supID4 = this.replyItemModel.getSupID();
                long supUser4 = this.replyItemModel.getSupUser();
                replayID2 = replayID4;
                replayUID2 = replayUID4;
                supID2 = supID4;
                supUser2 = supUser4;
            }
            doReplyFc(new RequestReplyFcBean(forumID, forumUser, replayID2, replayUID2, supID2, supUser2, content, this.mRespFcDetailBean.getRequiredVipLevel()), this.replyPosition);
            return;
        }
        RespFcListBean respFcListBean = this.mRespFcDetailBean;
        if (respFcListBean == null) {
            return;
        }
        long forumID2 = respFcListBean.getForumID();
        long forumUser2 = this.mRespFcDetailBean.getCreateBy();
        FcReplyBean fcReplyBean2 = this.commentItemModel;
        if (fcReplyBean2 == null || this.commentParentPosition <= 0) {
            replayID = forumID2;
            replayUID = forumUser2;
            supID = 0;
            supUser = 0;
        } else if (fcReplyBean2.getReplayID() == forumID2) {
            long replayID5 = this.commentItemModel.getCommentID();
            long replayUID5 = this.commentItemModel.getCreateBy();
            long supID5 = this.commentItemModel.getCommentID();
            long supUser5 = this.commentItemModel.getCreateBy();
            replayID = replayID5;
            replayUID = replayUID5;
            supID = supID5;
            supUser = supUser5;
        } else {
            long replayID6 = this.commentItemModel.getCommentID();
            long replayUID6 = this.commentItemModel.getCreateBy();
            long supID6 = this.commentItemModel.getSupID();
            long supUser6 = this.commentItemModel.getSupUser();
            replayID = replayID6;
            replayUID = replayUID6;
            supID = supID6;
            supUser = supUser6;
        }
        RequestReplyFcBean mRequestReplyFcBean = new RequestReplyFcBean(forumID2, forumUser2, replayID, replayUID, supID, supUser, content, this.mRespFcDetailBean.getRequiredVipLevel());
        mRequestReplyFcBean.setEntitys(atUserBeanList);
        doReplyFc(mRequestReplyFcBean, this.commentParentPosition);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcChildReplyListDialog.ChildReplyListListener
    public void onChildReplyListAction(View view, int index, int position, Object object) {
        if (index == FcDetailAdapter.Index_child_reply_click_avatar) {
            if (object instanceof FcReplyBean) {
                final FcReplyBean model = (FcReplyBean) object;
                FcChildReplyListDialog fcChildReplyListDialog = this.replyListDialog;
                if (fcChildReplyListDialog != null && fcChildReplyListDialog.isShowing()) {
                    this.replyListDialog.dismiss();
                }
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageDetailActivity.8
                    @Override // java.lang.Runnable
                    public void run() {
                        if (model.getCreateBy() == FcPageDetailActivity.this.getUserConfig().getCurrentUser().id) {
                            FcPageDetailActivity.this.onPresentFragment(new FcPageMineActivity());
                        } else {
                            FcPageDetailActivity.this.onPresentFragment(new FcPageOthersActivity(model.getCreator()));
                        }
                    }
                }, 500L);
                return;
            }
            return;
        }
        if (index == FcDetailAdapter.Index_child_reply_click_like && (object instanceof FcReplyBean)) {
            FcReplyBean model2 = (FcReplyBean) object;
            if (model2.isHasThumb()) {
                doCancelLikeFc(model2.getForumID(), model2.getForumUser(), model2.getCommentID(), model2.getCreateBy(), position);
            } else {
                doLike(model2.getForumID(), model2.getForumUser(), model2.getCommentID(), model2.getForumID(), position);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcChildReplyListDialog.ChildReplyListListener
    public void onChildReplyClick(View v, String receiver, FcReplyBean model, int parentPosition, int itemPosition, boolean isLongClick) {
        if (this.mChildReplyListAdapter != null) {
            if (isLongClick) {
                if (model != null) {
                    showDeleteBottomSheet(model, parentPosition, itemPosition);
                    return;
                }
                return;
            }
            this.replyItemModel = model;
            this.replyCommentPosition = parentPosition;
            this.replyPosition = itemPosition;
            RespFcListBean respFcListBean = this.mRespFcDetailBean;
            if (respFcListBean != null) {
                showReplyFcDialog(receiver, respFcListBean.getForumID(), this.mRespFcDetailBean.getCreateBy(), this.isShowAtUser, false, this.mRespFcDetailBean.isRecommend(), this.mRespFcDetailBean.getRequiredVipLevel());
            }
        }
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

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    protected void doLikeAfterViewChange(int position, boolean isLike, FcLikeBean data) {
        View viewByPosition;
        FcChildReplyListDialog fcChildReplyListDialog = this.replyListDialog;
        if (fcChildReplyListDialog != null && fcChildReplyListDialog.isShowing()) {
            int parentFcReplyPosition = this.mChildReplyListAdapter.getParentFcReplyPosition();
            if (position == 0 && parentFcReplyPosition < this.mAdapter.getItemCount() && (viewByPosition = this.layoutManager.findViewByPosition(parentFcReplyPosition)) != null) {
                MryTextView btnCommentLike = (MryTextView) viewByPosition.findViewById(R.attr.btn_like);
                FcReplyBean fcReplyBean = this.mAdapter.get(parentFcReplyPosition);
                fcReplyBean.setHasThumb(isLike);
                if (isLike) {
                    fcReplyBean.setThumbUp(this.mAdapter.get(parentFcReplyPosition).getThumbUp() + 1);
                } else {
                    fcReplyBean.setThumbUp(this.mAdapter.get(parentFcReplyPosition).getThumbUp() - 1);
                }
                if (btnCommentLike != null) {
                    btnCommentLike.setText(fcReplyBean.getThumbUp() > 0 ? String.valueOf(fcReplyBean.getThumbUp()) : "0");
                    btnCommentLike.setSelected(isLike);
                }
            }
            this.replyListDialog.doLike(position, isLike, data);
            return;
        }
        View viewByPosition2 = this.layoutManager.findViewByPosition(position);
        MryTextView btnLike = null;
        if (viewByPosition2 != null && (btnLike = (MryTextView) viewByPosition2.findViewById(R.attr.btn_like)) != null) {
            btnLike.setClickable(true);
        }
        if (data != null) {
            KLog.d("------position" + position + "  " + isLike);
            if (position == 0) {
                this.mAdapter.getFcContentBean().setHasThumb(isLike);
                if (isLike) {
                    this.mAdapter.getFcContentBean().setThumbUp(this.mAdapter.getFcContentBean().getThumbUp() + 1);
                } else {
                    this.mAdapter.getFcContentBean().setThumbUp(this.mAdapter.getFcContentBean().getThumbUp() - 1);
                }
                if (btnLike != null) {
                    btnLike.setText(this.mAdapter.getFcContentBean().getThumbUp() > 0 ? String.valueOf(this.mAdapter.getFcContentBean().getThumbUp()) : "0");
                    btnLike.setSelected(isLike);
                }
                this.mAdapter.doLikeUserChanged(data, isLike);
                return;
            }
            FcReplyBean fcReplyBean2 = this.mAdapter.get(position);
            fcReplyBean2.setHasThumb(isLike);
            if (isLike) {
                fcReplyBean2.setThumbUp(this.mAdapter.get(position).getThumbUp() + 1);
            } else {
                fcReplyBean2.setThumbUp(this.mAdapter.get(position).getThumbUp() - 1);
            }
            if (btnLike != null) {
                btnLike.setText(fcReplyBean2.getThumbUp() > 0 ? String.valueOf(fcReplyBean2.getThumbUp()) : "0");
                btnLike.setSelected(isLike);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    protected void doReplySuccAfterViewChange(FcReplyBean data, int replyParentPosition) {
        MryTextView btnReply;
        MryTextView btnReply2;
        FcChildReplyListDialog fcChildReplyListDialog = this.replyListDialog;
        if (fcChildReplyListDialog != null && fcChildReplyListDialog.isShowing()) {
            RespFcListBean fcContentBean = this.mAdapter.getFcContentBean();
            if (fcContentBean != null) {
                fcContentBean.setCommentCount(fcContentBean.getCommentCount() + 1);
                this.mAdapter.setFcContentData(fcContentBean);
                View viewByPosition = this.layoutManager.findViewByPosition(0);
                if (viewByPosition != null && (btnReply2 = (MryTextView) viewByPosition.findViewById(R.attr.btn_reply)) != null) {
                    btnReply2.setText(fcContentBean.getCommentCount() > 0 ? String.valueOf(fcContentBean.getCommentCount()) : "0");
                }
            }
            this.replyListDialog.doReply(data);
            FcChildReplyListDialog fcChildReplyListDialog2 = this.replyListDialog;
            if (fcChildReplyListDialog2 != null) {
                List<FcReplyBean> dataList = fcChildReplyListDialog2.getRealDataList();
                int commentPosition = this.replyCommentPosition;
                FcReplyBean fcReplyBean = this.mAdapter.get(commentPosition);
                if (dataList != null && fcReplyBean != null && fcReplyBean.getSubComment() != null) {
                    this.mAdapter.get(commentPosition).getSubComment().clear();
                    this.mAdapter.get(commentPosition).getSubComment().addAll(dataList);
                    this.mAdapter.get(commentPosition).setSubComments(dataList.size());
                    this.mAdapter.notifyItemChanged(commentPosition);
                    return;
                }
                return;
            }
            return;
        }
        RespFcListBean fcContentBean2 = this.mAdapter.getFcContentBean();
        if (fcContentBean2 != null) {
            fcContentBean2.setCommentCount(fcContentBean2.getCommentCount() + 1);
            this.mAdapter.setFcContentData(fcContentBean2);
            View viewByPosition2 = this.layoutManager.findViewByPosition(0);
            if (viewByPosition2 != null && (btnReply = (MryTextView) viewByPosition2.findViewById(R.attr.btn_reply)) != null) {
                btnReply.setText(fcContentBean2.getCommentCount() > 0 ? String.valueOf(fcContentBean2.getCommentCount()) : "0");
            }
        }
        if (replyParentPosition == 0 && this.mAdapter.getFcContentBean() != null) {
            if (this.mAdapter.getItemCount() >= 2 && this.mAdapter.getFooterSize() != 0) {
                this.mAdapter.getDataList().add(this.mAdapter.getItemCount() - 1, data);
                this.mAdapter.notifyItemInserted(r1.getItemCount() - 1);
                this.mAdapter.notifyItemRangeChanged(r1.getItemCount() - 1, this.mAdapter.getFooterSize());
                return;
            }
            ArrayList<FcReplyBean> moreList = new ArrayList<>();
            moreList.add(data);
            this.mAdapter.loadMore(moreList);
            return;
        }
        FcReplyBean fcReplyBean2 = this.mAdapter.get(replyParentPosition);
        if (fcReplyBean2 != null && data != null) {
            fcReplyBean2.setSubComments(fcReplyBean2.getSubComments() + 1);
            ArrayList<FcReplyBean> comments = fcReplyBean2.getSubComment();
            if (comments == null || comments.size() == 0) {
                comments = new ArrayList<>();
            }
            comments.add(data);
            fcReplyBean2.setSubComment(comments);
            this.mAdapter.notifyItemChanged(replyParentPosition);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    public void doDeleteReplySuccAfterViewChange(long forumId, long commentId, int parentPosition, int childPosition) {
        MryTextView btnReply;
        MryTextView btnReply2;
        FcChildReplyListDialog fcChildReplyListDialog = this.replyListDialog;
        if (fcChildReplyListDialog != null && fcChildReplyListDialog.isShowing()) {
            RespFcListBean fcContentBean = this.mAdapter.getFcContentBean();
            if (fcContentBean != null) {
                fcContentBean.setCommentCount(fcContentBean.getCommentCount() - 1);
                this.mAdapter.setFcContentData(fcContentBean);
                View viewByPosition = this.layoutManager.findViewByPosition(0);
                if (viewByPosition != null && (btnReply2 = (MryTextView) viewByPosition.findViewById(R.attr.btn_reply)) != null) {
                    btnReply2.setText(fcContentBean.getCommentCount() > 0 ? String.valueOf(fcContentBean.getCommentCount()) : "0");
                }
            }
            this.replyListDialog.doDeleteReply(childPosition);
            FcChildReplyListDialog fcChildReplyListDialog2 = this.replyListDialog;
            if (fcChildReplyListDialog2 != null) {
                List<FcReplyBean> dataList = fcChildReplyListDialog2.getRealDataList();
                FcReplyBean fcReplyBean = this.mAdapter.get(parentPosition);
                if (dataList != null && fcReplyBean != null && fcReplyBean.getSubComment() != null) {
                    this.mAdapter.get(parentPosition).getSubComment().clear();
                    this.mAdapter.get(parentPosition).getSubComment().addAll(dataList);
                    this.mAdapter.get(parentPosition).setSubComments(dataList.size());
                    this.mAdapter.notifyItemChanged(parentPosition);
                    return;
                }
                return;
            }
            return;
        }
        RespFcListBean fcContentBean2 = this.mAdapter.getFcContentBean();
        FcReplyBean fcReplyBean2 = this.mAdapter.get(parentPosition);
        if (fcReplyBean2 != null) {
            if (childPosition == -1) {
                fcContentBean2.setCommentCount((fcContentBean2.getCommentCount() - this.mAdapter.get(parentPosition).getSubComments()) - 1);
                this.mAdapter.getDataList().remove(parentPosition);
                this.mAdapter.notifyItemRemoved(parentPosition);
                FcDetailAdapter fcDetailAdapter = this.mAdapter;
                fcDetailAdapter.notifyItemRangeChanged(parentPosition, fcDetailAdapter.getItemCount() - parentPosition);
            } else {
                fcContentBean2.setCommentCount(fcContentBean2.getCommentCount() - 1);
                fcReplyBean2.setSubComments(fcReplyBean2.getSubComments() - 1);
                fcReplyBean2.getSubComment().remove(childPosition);
                this.mAdapter.notifyItemChanged(parentPosition);
            }
        }
        if (fcContentBean2 != null) {
            this.mAdapter.setFcContentData(fcContentBean2);
            View viewByPosition2 = this.layoutManager.findViewByPosition(0);
            if (viewByPosition2 != null && (btnReply = (MryTextView) viewByPosition2.findViewById(R.attr.btn_reply)) != null) {
                btnReply.setText(fcContentBean2.getCommentCount() > 0 ? String.valueOf(fcContentBean2.getCommentCount()) : "0");
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity, im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void onError(String msg) {
        FcToastUtils.show((CharSequence) (msg == null ? LocaleController.getString("friendscircle_home_request_fail", R.string.friendscircle_home_request_fail) : msg));
    }
}
