package com.bjz.comm.net.mvp.presenter;

import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.BResponseNoData;
import com.bjz.comm.net.bean.FcBgBean;
import com.bjz.comm.net.bean.FcIgnoreUserBean;
import com.bjz.comm.net.bean.FcLikeBean;
import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.bean.RequestReplyFcBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.model.FcCommItemModel;
import com.bjz.comm.net.utils.RxHelper;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes4.dex */
public class FcCommItemPresenter implements BaseFcContract.IFcCommItemPresenter {
    private BaseFcContract.IFcCommItemView mView;
    private String TAG = FcCommItemPresenter.class.getSimpleName();
    private final FcCommItemModel model = new FcCommItemModel();

    public FcCommItemPresenter(BaseFcContract.IFcCommItemView view) {
        this.mView = view;
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemPresenter
    public void getFCBackground(long userId) {
        this.model.getFcBackgroundUrl(userId, new DataListener<BResponse<FcBgBean>>() { // from class: com.bjz.comm.net.mvp.presenter.FcCommItemPresenter.1
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<FcBgBean> result) {
                if (result != null && result.isState()) {
                    FcCommItemPresenter.this.mView.getFcBackgroundSucc(result.Data);
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemPresenter
    public void doFollow(final long followUID, final int position) {
        this.model.doFollow(followUID, new DataListener<BResponseNoData>() { // from class: com.bjz.comm.net.mvp.presenter.FcCommItemPresenter.2
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponseNoData result) {
                if (result == null) {
                    FcCommItemPresenter.this.mView.doFollowFailed(null);
                } else if (result.isState()) {
                    FcCommItemPresenter.this.mView.doFollowSucc(followUID, position, result.Message);
                } else {
                    FcCommItemPresenter.this.mView.doFollowFailed(result.Message);
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcCommItemPresenter.this.mView.doFollowFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemPresenter
    public void doCancelFollowed(final long followUID, final int position) {
        this.model.doCancelFollowed(followUID, new DataListener<BResponseNoData>() { // from class: com.bjz.comm.net.mvp.presenter.FcCommItemPresenter.3
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponseNoData result) {
                if (result == null) {
                    FcCommItemPresenter.this.mView.doCancelFollowedFailed(null);
                } else if (result.isState()) {
                    FcCommItemPresenter.this.mView.doCancelFollowedSucc(followUID, position, result.Message);
                } else {
                    FcCommItemPresenter.this.mView.doCancelFollowedFailed(result.Message);
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcCommItemPresenter.this.mView.doCancelFollowedFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemPresenter
    public void doLike(final long forumID, long forumUID, long commentID, long commentUID, final int position) {
        this.model.doLike(forumID, forumUID, commentID, commentUID, new DataListener<BResponse<FcLikeBean>>() { // from class: com.bjz.comm.net.mvp.presenter.FcCommItemPresenter.4
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<FcLikeBean> result) {
                if (result == null) {
                    FcCommItemPresenter.this.mView.doLikeFailed(position, null);
                } else if (result.isState()) {
                    FcCommItemPresenter.this.mView.doLikeSucc(result.Data, forumID, position, result.Message);
                } else {
                    FcCommItemPresenter.this.mView.doLikeFailed(position, result.Message);
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcCommItemPresenter.this.mView.doLikeFailed(position, RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemPresenter
    public void doCancelLike(final long forumID, long forumUID, long commentID, long commentUID, final int position) {
        this.model.doCancelLike(forumID, forumUID, commentID, commentUID, new DataListener<BResponse<FcLikeBean>>() { // from class: com.bjz.comm.net.mvp.presenter.FcCommItemPresenter.5
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<FcLikeBean> result) {
                if (result == null) {
                    FcCommItemPresenter.this.mView.doCancelLikeFailed(position, null);
                } else if (result.isState()) {
                    FcCommItemPresenter.this.mView.doCancelLikeSucc(result.Data, forumID, position, result.Message);
                } else {
                    FcCommItemPresenter.this.mView.doCancelLikeFailed(position, result.Message);
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcCommItemPresenter.this.mView.doCancelLikeFailed(position, RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemPresenter
    public void doDeleteItem(final long forumID, final int position) {
        this.model.doDeleteItem(forumID, new DataListener<BResponseNoData>() { // from class: com.bjz.comm.net.mvp.presenter.FcCommItemPresenter.6
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponseNoData result) {
                if (result == null) {
                    FcCommItemPresenter.this.mView.doDeleteItemFailed(null);
                } else if (result.isState()) {
                    FcCommItemPresenter.this.mView.doDeleteItemSucc(forumID, position, result.Message);
                } else {
                    FcCommItemPresenter.this.mView.doDeleteItemFailed(result.Message);
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcCommItemPresenter.this.mView.doDeleteItemFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemPresenter
    public void doIgnoreItem(final long forumID, final int position) {
        this.model.doIgnoreItem(forumID, new DataListener<BResponseNoData>() { // from class: com.bjz.comm.net.mvp.presenter.FcCommItemPresenter.7
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponseNoData result) {
                if (result == null) {
                    FcCommItemPresenter.this.mView.doDeleteItemFailed(null);
                } else if (result.isState()) {
                    FcCommItemPresenter.this.mView.doIgnoreItemSucc(forumID, position, result.Message);
                } else {
                    FcCommItemPresenter.this.mView.doIgnoreItemFailed(result.Message);
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcCommItemPresenter.this.mView.doDeleteItemFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemPresenter
    public void doSetItemPermission(final long forumID, final int permission, final int position) {
        this.model.doSetItemPermission(forumID, permission, new DataListener<BResponseNoData>() { // from class: com.bjz.comm.net.mvp.presenter.FcCommItemPresenter.8
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponseNoData result) {
                if (result == null) {
                    FcCommItemPresenter.this.mView.doSetItemPermissionFailed(null);
                } else if (result.isState()) {
                    FcCommItemPresenter.this.mView.doSetItemPermissionSucc(forumID, permission, position, result.Message);
                } else {
                    FcCommItemPresenter.this.mView.doSetItemPermissionFailed(result.Message);
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcCommItemPresenter.this.mView.doSetItemPermissionFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemPresenter
    public void doAddIgnoreUser(final ArrayList<FcIgnoreUserBean> ignores) {
        this.model.doAddIgnoreUser(ignores, new DataListener<BResponse<ArrayList<FcIgnoreUserBean>>>() { // from class: com.bjz.comm.net.mvp.presenter.FcCommItemPresenter.9
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<ArrayList<FcIgnoreUserBean>> result) {
                if (result != null) {
                    if (result.isState()) {
                        FcCommItemPresenter.this.mView.doAddIgnoreUserSucc(ignores, result.Message);
                    } else {
                        FcCommItemPresenter.this.mView.onError(result.Message);
                    }
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcCommItemPresenter.this.mView.doAddIgnoreUserFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemPresenter
    public void doDeleteIgnoreUser(final ArrayList<FcIgnoreUserBean> ignores) {
        this.model.doDeleteIgnoreUser(ignores, new DataListener<BResponse<ArrayList<FcIgnoreUserBean>>>() { // from class: com.bjz.comm.net.mvp.presenter.FcCommItemPresenter.10
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<ArrayList<FcIgnoreUserBean>> result) {
                if (result == null) {
                    FcCommItemPresenter.this.mView.onError(null);
                } else if (result.isState()) {
                    FcCommItemPresenter.this.mView.doDeleteIgnoreUserSucc(ignores, result.Message);
                } else {
                    FcCommItemPresenter.this.mView.onError(result.Message);
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcCommItemPresenter.this.mView.onError(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemPresenter
    public void doReply(final RequestReplyFcBean bean, final int replyParentPosition) {
        this.model.doReply(bean, new DataListener<BResponse<FcReplyBean>>() { // from class: com.bjz.comm.net.mvp.presenter.FcCommItemPresenter.11
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<FcReplyBean> result) {
                if (result == null) {
                    FcCommItemPresenter.this.mView.doReplyFailed(replyParentPosition, bean.getSupID() == 0 && bean.getSupUser() == 0, null, null);
                } else if (!result.isState() || result.Data == null) {
                    FcCommItemPresenter.this.mView.doReplyFailed(replyParentPosition, bean.getSupID() == 0 && bean.getSupUser() == 0, result.Code, result.Message);
                } else {
                    FcCommItemPresenter.this.mView.doReplySucc(result.Data, replyParentPosition);
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcCommItemPresenter.this.mView.onError(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemPresenter
    public void doDeleteComment(final long commentID, final long forumID, long forumUser, final int parentId, final int childId) {
        this.model.doDeleteComment(commentID, forumID, forumUser, new DataListener<BResponseNoData>() { // from class: com.bjz.comm.net.mvp.presenter.FcCommItemPresenter.12
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponseNoData result) {
                if (result == null) {
                    FcCommItemPresenter.this.mView.onError(null);
                } else if (result.isState()) {
                    FcCommItemPresenter.this.mView.doDeleteReplySucc(forumID, commentID, parentId, childId);
                } else {
                    FcCommItemPresenter.this.mView.onError(result.Message);
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcCommItemPresenter.this.mView.onError(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.base.IBPresenter
    public void unSubscribeTask() {
        this.model.unSubscribeTask();
    }
}
