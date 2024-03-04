package io.xjar.key;

import java.util.Date;

public class CustomField {
    private Date beginTime;
    private Date endTime;
    private Boolean md5Enabled;
    private Boolean agentEnabled;
    private String mac;

    private CustomField() {
    }

    public CustomField(Date beginTime, Date endTime, Boolean agentEnabled, Boolean md5Enabled, String mac) {
        this.beginTime = beginTime;
        this.mac = mac;
        this.agentEnabled = agentEnabled;
        this.md5Enabled = md5Enabled;
        this.endTime = endTime;
    }

    public Date getBeginTime() {
        return beginTime;
    }

    public Date getEndTime() {
        return endTime;
    }

    public Boolean getMd5Enabled() {
        return md5Enabled;
    }

    public Boolean getAgentEnabled() {
        return agentEnabled;
    }

    public String getMac() {
        return mac;
    }
}
