package com.bjz.comm.net.mvp.presenter;

import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.RespFcUserStatisticsBean;
import com.bjz.comm.net.bean.RespOthersFcListBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.model.FcPageOthersModel;
import com.bjz.comm.net.utils.RxHelper;

/* JADX INFO: loaded from: classes4.dex */
public class FcPageOthersPresenter implements BaseFcContract.IFcPageOthersPresenter {
    private BaseFcContract.IFcPageOthersView mView;
    private FcPageOthersModel model;

    public FcPageOthersPresenter(BaseFcContract.IFcPageOthersView view) {
        this.model = null;
        this.mView = view;
        if (0 == 0) {
            this.model = new FcPageOthersModel();
        }
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageOthersPresenter
    public void getActionCount(long userId) {
        this.model.getActionCount(userId, new DataListener<BResponse<RespFcUserStatisticsBean>>() { // from class: com.bjz.comm.net.mvp.presenter.FcPageOthersPresenter.1
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<RespFcUserStatisticsBean> result) {
                if (result == null) {
                    FcPageOthersPresenter.this.mView.onError(null);
                } else if (result.isState()) {
                    FcPageOthersPresenter.this.mView.getActionCountSucc(result.Data);
                } else {
                    FcPageOthersPresenter.this.mView.onError(result.Message);
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcPageOthersPresenter.this.mView.onError(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageOthersPresenter
    public void checkIsFollowed(long followUID) {
        this.model.checkIsFollowed(followUID, new DataListener<BResponse<Boolean>>() { // from class: com.bjz.comm.net.mvp.presenter.FcPageOthersPresenter.2
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<Boolean> result) {
                if (result == null) {
                    FcPageOthersPresenter.this.mView.onError(null);
                } else if (result.isState()) {
                    FcPageOthersPresenter.this.mView.checkIsFollowedSucc(result.Data);
                } else {
                    FcPageOthersPresenter.this.mView.onError(result.Message);
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcPageOthersPresenter.this.mView.onError(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageOthersPresenter
    public void getFCList(int limit, long forumID, long userId, int roundNum) {
        this.model.getFCList(limit, forumID, userId, roundNum, new DataListener<BResponse<RespOthersFcListBean>>() { // from class: com.bjz.comm.net.mvp.presenter.FcPageOthersPresenter.3
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<RespOthersFcListBean> result) {
                if (result == null) {
                    FcPageOthersPresenter.this.mView.getFCListFailed(null);
                } else if (result.isState()) {
                    FcPageOthersPresenter.this.mView.getFCListSucc(result.Code, result.Data);
                } else {
                    FcPageOthersPresenter.this.mView.getFCListFailed(result.Message);
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcPageOthersPresenter.this.mView.getFCListFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.base.IBPresenter
    public void unSubscribeTask() {
        this.model.unSubscribeTask();
    }
}
