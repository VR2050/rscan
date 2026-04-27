package com.bjz.comm.net.mvp.presenter;

import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.BResponseNoData;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.bean.RespFcUserStatisticsBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.model.FcPageMineModel;
import com.bjz.comm.net.utils.RxHelper;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes4.dex */
public class FcPageMinePresenter implements BaseFcContract.IFcPageMinePresenter {
    BaseFcContract.IFcPageMineView mView;
    private FcPageMineModel model;

    public FcPageMinePresenter(BaseFcContract.IFcPageMineView view) {
        this.model = null;
        this.mView = view;
        if (0 == 0) {
            this.model = new FcPageMineModel();
        }
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageMinePresenter
    public void getFCList(int limit, long forumID) {
        this.model.getFCList(limit, forumID, new DataListener<BResponse<ArrayList<RespFcListBean>>>() { // from class: com.bjz.comm.net.mvp.presenter.FcPageMinePresenter.1
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<ArrayList<RespFcListBean>> result) {
                if (result != null) {
                    if (result.isState()) {
                        FcPageMinePresenter.this.mView.getFCListSucc(result.Data == null ? new ArrayList<>() : result.Data);
                        return;
                    } else {
                        FcPageMinePresenter.this.mView.getFCListFailed(result.Message);
                        return;
                    }
                }
                FcPageMinePresenter.this.mView.getFCListFailed(null);
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcPageMinePresenter.this.mView.getFCListFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageMinePresenter
    public void getActionCount(long userId) {
        this.model.getActionCount(userId, new DataListener<BResponse<RespFcUserStatisticsBean>>() { // from class: com.bjz.comm.net.mvp.presenter.FcPageMinePresenter.2
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<RespFcUserStatisticsBean> result) {
                if (result != null) {
                    if (result.isState()) {
                        FcPageMinePresenter.this.mView.getActionCountSucc(result.Data);
                        return;
                    } else {
                        FcPageMinePresenter.this.mView.onError(result.Message);
                        return;
                    }
                }
                FcPageMinePresenter.this.mView.onError(null);
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcPageMinePresenter.this.mView.onError(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageMinePresenter
    public void setFcBackground(final String homeBackground) {
        this.model.setFcBackground(homeBackground, new DataListener<BResponseNoData>() { // from class: com.bjz.comm.net.mvp.presenter.FcPageMinePresenter.3
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponseNoData result) {
                if (result != null) {
                    if (result.isState()) {
                        FcPageMinePresenter.this.mView.setFcBackgroundSucc(homeBackground, result.Message);
                        return;
                    } else {
                        FcPageMinePresenter.this.mView.setFcBackgroundFailed(result.Message);
                        return;
                    }
                }
                FcPageMinePresenter.this.mView.setFcBackgroundFailed(null);
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcPageMinePresenter.this.mView.setFcBackgroundFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.base.IBPresenter
    public void unSubscribeTask() {
        this.model.unSubscribeTask();
    }
}
