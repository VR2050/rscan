package im.uwrkaxlmjj.ui.hui.friendscircle_v1.base;

import android.content.SharedPreferences;
import android.graphics.Color;
import android.text.TextUtils;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.SPConstant;
import com.bjz.comm.net.bean.FcBgBean;
import com.bjz.comm.net.bean.FcIgnoreUserBean;
import com.bjz.comm.net.bean.FcLikeBean;
import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.bean.RequestReplyFcBean;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.presenter.FcCommItemPresenter;
import com.bjz.comm.net.utils.HttpUtils;
import com.socks.library.KLog;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.dialogs.FcDialog;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.FcDialogUtil;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcCommMenuDialog;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcDoReplyDialog;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public abstract class CommFcListActivity extends BaseFcActivity implements BaseFcContract.IFcCommItemView, FcDoReplyDialog.OnFcDoReplyListener {
    private String TAG = getClass().getSimpleName();
    private FcCommMenuDialog dialogDeleteComment;
    private FcDoReplyDialog fcDoReplyDialog;
    protected RecyclerView.LayoutManager layoutManager;
    private FcCommItemPresenter mCommItemPresenter;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        this.mCommItemPresenter = new FcCommItemPresenter(this);
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        FcDoReplyDialog fcDoReplyDialog = this.fcDoReplyDialog;
        if (fcDoReplyDialog != null) {
            fcDoReplyDialog.onDestroy();
        }
        FcCommItemPresenter fcCommItemPresenter = this.mCommItemPresenter;
        if (fcCommItemPresenter != null) {
            fcCommItemPresenter.unSubscribeTask();
        }
    }

    protected void showDeleteBottomSheet(final FcReplyBean model, final int itemPosition, final int replyPosition) {
        if (getParentActivity() != null && model.getCreateBy() == getUserConfig().getCurrentUser().id) {
            List<String> list = new ArrayList<>();
            list.add(LocaleController.getString("Delete", R.string.Delete));
            FcCommMenuDialog fcCommMenuDialog = new FcCommMenuDialog(getParentActivity(), list, (List<Integer>) null, Color.parseColor("#FFFF4D3B"), new FcCommMenuDialog.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity.1
                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcCommMenuDialog.RecyclerviewItemClickCallBack
                public void onRecyclerviewItemClick(int position) {
                    if (position == 0) {
                        CommFcListActivity.this.deleteReply(model, itemPosition, replyPosition);
                    }
                }
            }, 1);
            this.dialogDeleteComment = fcCommMenuDialog;
            if (fcCommMenuDialog.isShowing()) {
                this.dialogDeleteComment.dismiss();
            } else {
                this.dialogDeleteComment.show();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void deleteReply(final FcReplyBean model, final int itemPosition, final int replyPosition) {
        FcDialogUtil.chooseIsDeleteCommentDialog(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.-$$Lambda$CommFcListActivity$QS2hFtjzF9SUyEvT5gquuJlfX_o
            @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
            public final void onClick(View view) {
                this.f$0.lambda$deleteReply$0$CommFcListActivity(model, itemPosition, replyPosition, view);
            }
        }, null);
    }

    public /* synthetic */ void lambda$deleteReply$0$CommFcListActivity(FcReplyBean model, int itemPosition, int replyPosition, View dialog) {
        doDeleteComment(model, itemPosition, replyPosition);
    }

    protected void showDeleteBottomSheet(final RespFcListBean model, final int itemPosition, final int replyPosition) {
        if (getParentActivity() != null && model.getComments().get(replyPosition).getCreateBy() == getUserConfig().getCurrentUser().id) {
            if (this.dialogDeleteComment == null) {
                List<String> list = new ArrayList<>();
                list.add(LocaleController.getString("Delete", R.string.Delete));
                this.dialogDeleteComment = new FcCommMenuDialog(getParentActivity(), list, (List<Integer>) null, Color.parseColor("#FFFF4D3B"), new FcCommMenuDialog.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity.2
                    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcCommMenuDialog.RecyclerviewItemClickCallBack
                    public void onRecyclerviewItemClick(int position) {
                        if (position == 0) {
                            CommFcListActivity.this.deleteReply(model, itemPosition, replyPosition);
                        }
                    }
                }, 1);
            }
            if (this.dialogDeleteComment.isShowing()) {
                this.dialogDeleteComment.dismiss();
            } else {
                this.dialogDeleteComment.show();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void deleteReply(final RespFcListBean model, final int itemPosition, final int replyPosition) {
        FcDialogUtil.chooseIsDeleteCommentDialog(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.-$$Lambda$CommFcListActivity$tuxsOyNOVxKEQmjwuNBa7Cwhqcc
            @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
            public final void onClick(View view) {
                this.f$0.lambda$deleteReply$1$CommFcListActivity(model, itemPosition, replyPosition, view);
            }
        }, null);
    }

    public /* synthetic */ void lambda$deleteReply$1$CommFcListActivity(RespFcListBean model, int itemPosition, int replyPosition, View dialog) {
        doDeleteComment(model, itemPosition, replyPosition);
    }

    protected void showReplyFcDialog(String hint, long forumId, long forumUId, boolean isEnableAtUser, boolean isComment, boolean isRecommend, int requiredLevel) {
        if (this.fcDoReplyDialog == null) {
            FcDoReplyDialog fcDoReplyDialog = new FcDoReplyDialog(getParentActivity());
            this.fcDoReplyDialog = fcDoReplyDialog;
            fcDoReplyDialog.setListener(this);
        }
        this.fcDoReplyDialog.show(hint, forumId, isEnableAtUser, isComment);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        dismissFcDoReplyDialog();
        super.onPause();
    }

    protected void dismissFcDoReplyDialog() {
        FcDoReplyDialog fcDoReplyDialog = this.fcDoReplyDialog;
        if (fcDoReplyDialog != null && fcDoReplyDialog.isShowing()) {
            this.fcDoReplyDialog.saveUnPostContent();
            this.fcDoReplyDialog.dismiss();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcDoReplyDialog.OnFcDoReplyListener
    public void startFragment(BaseFragment baseFragment) {
        if (baseFragment != null) {
            presentFragment(baseFragment);
        }
    }

    protected void loadFcBackground(long id) {
        if (getUserConfig().getCurrentUser().id == id) {
            SharedPreferences sharedPreferences = ApplicationLoader.applicationContext.getSharedPreferences(SPConstant.SP_SYSTEM_CONFIG, 0);
            String backStr = sharedPreferences.getString("fc_bg" + getUserConfig().getCurrentUser().id, "");
            KLog.d("-------getBG    " + backStr + "   ' fc_bg" + getUserConfig().getCurrentUser().id);
            if (!TextUtils.isEmpty(backStr)) {
                setFcBackground(backStr);
            }
        }
        this.mCommItemPresenter.getFCBackground(id);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void getFcBackgroundSucc(FcBgBean result) {
        if (result != null && !TextUtils.isEmpty(result.getHomeBackground())) {
            setFcBackground(HttpUtils.getInstance().getDownloadFileUrl() + result.getHomeBackground());
            if (getUserConfig().getCurrentUser().id == result.getUserID()) {
                saveFcBackground(HttpUtils.getInstance().getDownloadFileUrl() + result.getHomeBackground());
            }
        }
    }

    protected void saveFcBackground(String path) {
        SharedPreferences sharedPreferences = ApplicationLoader.applicationContext.getSharedPreferences(SPConstant.SP_SYSTEM_CONFIG, 0);
        sharedPreferences.edit().putString("fc_bg" + getUserConfig().getCurrentUser().id, path).commit();
    }

    protected void setFcBackground(String path) {
    }

    protected void doFollow(int position, RespFcListBean mRespFcListBean) {
        this.mCommItemPresenter.doFollow(mRespFcListBean.getCreateBy(), position);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void doFollow(long userId) {
        this.mCommItemPresenter.doFollow(userId, -1);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doFollowSucc(long userId, int position, String msg) {
        FcToastUtils.show((CharSequence) LocaleController.getString("friendscircle_attention_user_succ", R.string.friendscircle_attention_user_succ));
        doFollowAfterViewChange(position, true);
        NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.fcFollowStatusUpdate, this.TAG, Long.valueOf(userId), true);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doFollowFailed(String msg) {
        FcToastUtils.show((CharSequence) (msg == null ? LocaleController.getString("friendscircle_attention_user_fail", R.string.friendscircle_attention_user_fail) : msg));
    }

    protected void doFollowAfterViewChange(int position, boolean isFollow) {
    }

    protected void doCancelFollowed(int position, RespFcListBean mRespFcListBean) {
        this.mCommItemPresenter.doCancelFollowed(mRespFcListBean.getCreateBy(), position);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void doCancelFollowed(long userId) {
        this.mCommItemPresenter.doCancelFollowed(userId, -1);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doCancelFollowedSucc(long userId, int position, String msg) {
        FcToastUtils.show((CharSequence) msg);
        doFollowAfterViewChange(position, false);
        NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.fcFollowStatusUpdate, this.TAG, Long.valueOf(userId), false);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doCancelFollowedFailed(String msg) {
        FcToastUtils.show((CharSequence) (msg == null ? LocaleController.getString("friendscircle_attention_user_cancel_fail", R.string.friendscircle_attention_user_cancel_fail) : msg));
    }

    protected void doLike(long forumId, long forumUId, long commentId, long commentUId, int position) {
        this.mCommItemPresenter.doLike(forumId, forumUId, commentId, commentUId, position);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doLikeSucc(FcLikeBean data, long forumID, int position, String msg) {
        FcToastUtils.show((CharSequence) LocaleController.getString("SOKULF1", R.string.SOKULF1));
        doLikeAfterViewChange(position, true, data);
        NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.fcLikeStatusUpdate, this.TAG, data, true);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doLikeFailed(int position, String msg) {
        FcToastUtils.show((CharSequence) (msg == null ? LocaleController.getString("friendscircle_home_request_fail", R.string.friendscircle_home_request_fail) : msg));
        doLikeAfterViewChange(position, false, null);
    }

    protected void doCancelLikeFc(long forumId, long forumUID, long commentId, long commentUID, int position) {
        this.mCommItemPresenter.doCancelLike(forumId, forumUID, commentId, commentUID, position);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doCancelLikeSucc(FcLikeBean data, long forumID, int position, String msg) {
        FcToastUtils.show((CharSequence) LocaleController.getString("SOKUUF1", R.string.SOKUUF1));
        doLikeAfterViewChange(position, false, data);
        NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.fcLikeStatusUpdate, this.TAG, data, false);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doCancelLikeFailed(int position, String msg) {
        FcToastUtils.show((CharSequence) (msg == null ? LocaleController.getString("friendscircle_home_request_fail", R.string.friendscircle_home_request_fail) : msg));
        doLikeAfterViewChange(position, false, null);
    }

    protected void doLikeAfterViewChange(int position, boolean isLike, FcLikeBean data) {
    }

    protected void doDeleteItem(int position, RespFcListBean mRespFcListBean) {
        this.mCommItemPresenter.doDeleteItem(mRespFcListBean.getForumID(), position);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doDeleteItemSucc(long forumID, int position, String msg) {
        FcToastUtils.show((CharSequence) LocaleController.getString("fc_delete_item_succ", R.string.fc_delete_item_succ));
        doDeleteItemAfterViewChange(forumID, position);
        NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.fcIgnoreOrDeleteItem, this.TAG, Long.valueOf(forumID));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doDeleteItemFailed(String msg) {
        FcToastUtils.show((CharSequence) (msg == null ? LocaleController.getString("friendscircle_delete_data_fail", R.string.fc_delete_item_failed) : msg));
    }

    protected void doDeleteItemAfterViewChange(long forumId, int position) {
    }

    protected void setFcItemPermission(RespFcListBean mRespFcListBean, int status, int position) {
        this.mCommItemPresenter.doSetItemPermission(mRespFcListBean.getForumID(), status, position);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doSetItemPermissionSucc(long forumId, int permission, int position, String msg) {
        if (permission == 1) {
            FcToastUtils.show((CharSequence) LocaleController.getString("fc_set_fc_content_public_succ", R.string.fc_set_fc_content_public_succ));
        } else if (permission == 2) {
            FcToastUtils.show((CharSequence) LocaleController.getString("fc_set_fc_content_private_succ", R.string.fc_set_fc_content_private_succ));
        }
        doSetItemPermissionAfterViewChange(forumId, permission, position);
        NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.fcPermissionStatusUpdate, this.TAG, Long.valueOf(forumId), Integer.valueOf(permission));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doSetItemPermissionFailed(String msg) {
        FcToastUtils.show((CharSequence) (msg == null ? LocaleController.getString("friendscircle_set_fail", R.string.friendscircle_set_fail) : msg));
    }

    protected void doSetItemPermissionAfterViewChange(long forumId, int permission, int position) {
    }

    protected void doIgnoreItem(int position, RespFcListBean mRespFcListBean) {
        this.mCommItemPresenter.doIgnoreItem(mRespFcListBean.getForumID(), position);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doIgnoreItemSucc(long forumID, int position, String msg) {
        FcToastUtils.show((CharSequence) LocaleController.getString("friendscircle_hide_dynamic_success", R.string.friendscircle_hide_dynamic_success));
        doIgnoreItemAfterViewChange(forumID, position);
        NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.fcIgnoreOrDeleteItem, this.TAG, Long.valueOf(forumID));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doIgnoreItemFailed(String msg) {
        FcToastUtils.show((CharSequence) (msg == null ? LocaleController.getString("friendscircle_hide_dynamic_fail", R.string.friendscircle_hide_dynamic_fail) : msg));
    }

    protected void doIgnoreItemAfterViewChange(long forumId, int position) {
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void doAddIgnoreUser(ArrayList<FcIgnoreUserBean> ignores) {
        this.mCommItemPresenter.doAddIgnoreUser(ignores);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doAddIgnoreUserSucc(ArrayList<FcIgnoreUserBean> ignores, String msg) {
        FcToastUtils.show((CharSequence) msg);
        doSetIgnoreUserAfterViewChange(true, ignores);
        NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.fcIgnoreUser, this.TAG, ignores);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doAddIgnoreUserFailed(String msg) {
        FcToastUtils.show((CharSequence) msg);
    }

    public void doDeleteIgnoreUser(ArrayList<FcIgnoreUserBean> ignores) {
        this.mCommItemPresenter.doDeleteIgnoreUser(ignores);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doDeleteIgnoreUserSucc(ArrayList<FcIgnoreUserBean> ignores, String msg) {
        FcToastUtils.show((CharSequence) msg);
        doSetIgnoreUserAfterViewChange(false, ignores);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doDeleteIgnoreUserFiled(String msg) {
        FcToastUtils.show((CharSequence) msg);
    }

    protected void doSetIgnoreUserAfterViewChange(boolean isIgnore, ArrayList<FcIgnoreUserBean> ignores) {
    }

    public void doReplyFc(RequestReplyFcBean requestReplyFcBean, int replyParentPosition) {
        this.mCommItemPresenter.doReply(requestReplyFcBean, replyParentPosition);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doReplySucc(FcReplyBean data, int replyParentPosition) {
        if (data != null && data.getReplayID() == data.getForumID() && data.getReplayUID() == data.getForumUser()) {
            FcToastUtils.show((CharSequence) LocaleController.getString(R.string.friendscircle_home_comment_success));
        } else {
            FcToastUtils.show((CharSequence) LocaleController.getString(R.string.friendscircle_home_reply_success));
        }
        doReplySuccAfterViewChange(data, replyParentPosition);
        NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.fcReplyItem, this.TAG, data);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doReplyFailed(int replyParentPosition, boolean isComment, String code, String msg) {
        if (TextUtils.isEmpty(msg)) {
            if (isComment) {
                onError(LocaleController.getString(R.string.friendscircle_home_comment_fail));
                return;
            } else {
                onError(LocaleController.getString(R.string.friendscircle_home_reply_fail));
                return;
            }
        }
        onError(msg);
    }

    protected void doReplySuccAfterViewChange(FcReplyBean data, int replyParentPosition) {
    }

    public void doDeleteComment(RespFcListBean model, int itemPosition, int replyPosition) {
        FcReplyBean fcReplyBean = model.getComments().get(replyPosition);
        long commentID = fcReplyBean.getCommentID();
        long forumID = fcReplyBean.getForumID();
        long forumUser = fcReplyBean.getForumUser();
        this.mCommItemPresenter.doDeleteComment(commentID, forumID, forumUser, itemPosition, replyPosition);
    }

    public void doDeleteComment(FcReplyBean replyBean, int itemPosition, int replyPosition) {
        long commentID = replyBean.getCommentID();
        long forumID = replyBean.getForumID();
        long forumUser = replyBean.getForumUser();
        this.mCommItemPresenter.doDeleteComment(commentID, forumID, forumUser, itemPosition, replyPosition);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doDeleteReplySucc(long forumId, long commentId, int parentPosition, int childPosition) {
        FcToastUtils.show((CharSequence) LocaleController.getString(R.string.fc_delete_item_succ));
        doDeleteReplySuccAfterViewChange(forumId, commentId, parentPosition, childPosition);
        NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.fcDeleteReplyItem, this.TAG, Long.valueOf(forumId), Long.valueOf(commentId));
    }

    protected void doDeleteReplySuccAfterViewChange(long forumId, long commentId, int parentPosition, int childPosition) {
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void onError(String msg) {
        FcToastUtils.show((CharSequence) (msg == null ? LocaleController.getString("friendscircle_publish_server_busy", R.string.friendscircle_publish_server_busy) : msg));
    }

    public String getTAG() {
        return this.TAG;
    }
}
