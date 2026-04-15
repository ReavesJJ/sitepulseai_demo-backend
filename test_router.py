from monitoring_router import register_tenant, route_monitoring_event


def run_test():

    client_id = "TEST_CLIENT"

    # Simulate 5 domains (safe test load)
    domains = [
        "sitepulseai.com",
        "example.com",
        "testsite.org",
        "demo.io",
        "alpha-beta.net"
    ]

    print("\n=== REGISTERING TENANT ===")
    register_tenant(client_id, domains)

    print("\n=== STARTING MULTI-DOMAIN ROUTE TEST ===")
    results = route_monitoring_event(client_id)

    print("\n=== TEST RESULTS ===")
    for r in results:
        print(r)

    print("\n=== TEST COMPLETE ===")


if __name__ == "__main__":
    run_test()