docker build -t blueapp/authentication:0.0.2 . &&
kubectl scale --replicas=0 deployment deployment --namespace=authentication &&
kubectl scale --replicas=2 deployment deployment --namespace=authentication
