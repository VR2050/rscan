package com.bjz.comm.net.mvp.presenter;

import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.model.FcPageFollowedModel;
import com.bjz.comm.net.utils.RxHelper;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes4.dex */
public class FcPageFollowedPresenter implements BaseFcContract.IFcPageFollowedPresenter {
    BaseFcContract.IFcPageFollowedView mView;
    private FcPageFollowedModel model;

    public FcPageFollowedPresenter(BaseFcContract.IFcPageFollowedView view) {
        this.model = null;
        this.mView = view;
        if (0 == 0) {
            this.model = new FcPageFollowedModel();
        }
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageFollowedPresenter
    public void getFcList(int limit, long forumID) {
        this.model.getFcList(limit, forumID, new DataListener<BResponse<ArrayList<RespFcListBean>>>() { // from class: com.bjz.comm.net.mvp.presenter.FcPageFollowedPresenter.1
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<ArrayList<RespFcListBean>> result) {
                if (result != null) {
                    if (result.isState()) {
                        FcPageFollowedPresenter.this.mView.getFcListSucc(result.Data == null ? new ArrayList<>() : result.Data);
                        return;
                    } else {
                        FcPageFollowedPresenter.this.mView.getFcListFailed(result.Message);
                        return;
                    }
                }
                FcPageFollowedPresenter.this.mView.getFcListFailed(null);
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcPageFollowedPresenter.this.mView.getFcListFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.base.IBPresenter
    public void unSubscribeTask() {
        this.model.unSubscribeTask();
    }
}
