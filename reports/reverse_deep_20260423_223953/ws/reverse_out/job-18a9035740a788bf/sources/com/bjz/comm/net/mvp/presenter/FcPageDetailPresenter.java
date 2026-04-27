package com.bjz.comm.net.mvp.presenter;

import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.bean.RespFcLikesBean;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.bean.RespFcReplyBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.model.FcPageDetailModel;
import com.bjz.comm.net.utils.RxHelper;

/* JADX INFO: loaded from: classes4.dex */
public class FcPageDetailPresenter implements BaseFcContract.IFcPageDetailPresenter {
    BaseFcContract.IFcPageDetailView mView;
    private FcPageDetailModel model;

    public FcPageDetailPresenter(BaseFcContract.IFcPageDetailView view) {
        this.model = null;
        this.mView = view;
        if (0 == 0) {
            this.model = new FcPageDetailModel();
        }
    }

    @Override // com.bjz.comm.net.base.IBPresenter
    public void unSubscribeTask() {
        this.model.unSubscribeTask();
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailPresenter
    public void getDetail(long forumID, long forumUserId) {
        this.model.getDetail(forumID, forumUserId, new DataListener<BResponse<RespFcListBean>>() { // from class: com.bjz.comm.net.mvp.presenter.FcPageDetailPresenter.1
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<RespFcListBean> result) {
                if (result != null) {
                    if (result.isState()) {
                        FcPageDetailPresenter.this.mView.getDetailSucc(result.Data);
                        return;
                    } else {
                        FcPageDetailPresenter.this.mView.getDetailFailed(result.Message);
                        return;
                    }
                }
                FcPageDetailPresenter.this.mView.getDetailFailed(null);
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcPageDetailPresenter.this.mView.getDetailFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailPresenter
    public void getComments(long forumID, long commentId, long forumUserId, int limit) {
        this.model.getComments(forumID, commentId, forumUserId, limit, new DataListener<BResponse<RespFcReplyBean>>() { // from class: com.bjz.comm.net.mvp.presenter.FcPageDetailPresenter.2
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<RespFcReplyBean> result) {
                if (result != null && result.Data != null) {
                    if (result.isState()) {
                        FcPageDetailPresenter.this.mView.getCommentsSucc(result.Data.getComments());
                        return;
                    } else {
                        FcPageDetailPresenter.this.mView.getCommentsFailed(result.Message);
                        return;
                    }
                }
                FcPageDetailPresenter.this.mView.getCommentsFailed(null);
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcPageDetailPresenter.this.mView.getCommentsFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailPresenter
    public void getReplyList(final FcReplyBean parentFcReplyBean, final int parentFcReplyPosition, long commentId, int limit) {
        this.model.getReplyList(parentFcReplyBean, commentId, limit, new DataListener<BResponse<RespFcReplyBean>>() { // from class: com.bjz.comm.net.mvp.presenter.FcPageDetailPresenter.3
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<RespFcReplyBean> result) {
                if (result != null && result.Data != null) {
                    if (result.isState()) {
                        FcPageDetailPresenter.this.mView.getReplyListSucc(parentFcReplyBean, parentFcReplyPosition, result.Data.getComments());
                        return;
                    } else {
                        FcPageDetailPresenter.this.mView.getReplyListFailed(parentFcReplyBean, parentFcReplyPosition, result.Message);
                        return;
                    }
                }
                FcPageDetailPresenter.this.mView.getReplyListFailed(parentFcReplyBean, parentFcReplyPosition, null);
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcPageDetailPresenter.this.mView.getReplyListFailed(parentFcReplyBean, parentFcReplyPosition, RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailPresenter
    public void getLikeUserList(long forumId, long thumbId, int limit) {
        this.model.getLikeUserList(forumId, thumbId, limit, new DataListener<BResponse<RespFcLikesBean>>() { // from class: com.bjz.comm.net.mvp.presenter.FcPageDetailPresenter.4
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<RespFcLikesBean> result) {
                if (result != null && result.Data != null) {
                    if (result.isState()) {
                        FcPageDetailPresenter.this.mView.getLikeUserListSucc(result.Data);
                        return;
                    } else {
                        FcPageDetailPresenter.this.mView.getLikeUserListFiled(result.Message);
                        return;
                    }
                }
                FcPageDetailPresenter.this.mView.getLikeUserListFiled(null);
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcPageDetailPresenter.this.mView.getLikeUserListFiled(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }
}
