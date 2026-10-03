from analyzer import is_suspicious

def test_suspicious_true():
    moments = [100, 200, 400]
    suspicious = is_suspicious(moments)
    assert suspicious == True

def test_suspicious_false():
    moments = [1000, 5000, 9000]
    suspicious = is_suspicious(moments)
    assert suspicious == False