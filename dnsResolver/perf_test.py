from constants import WEBSITES
from dns_resolver import find_ip
from datetime import datetime as dt

import matplotlib.pyplot as plt
import numpy as np
import dns.resolver


EXPERIMENTAL_COUNT = 10


def resolver_factory(local_dns):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = local_dns
    return resolver


def performance_test(resolver, custom=False):
    averages = []
    for website in WEBSITES:
        total_tt = 0
        for count in range(EXPERIMENTAL_COUNT):
            start_timer = dt.now()
            if custom:
                resolver(website, dns.rdatatype.A)
            else:
                resolver.resolve(website, 'A')
            stop_timer = dt.now()
            time_taken = (stop_timer - start_timer).total_seconds() * 1000
            total_tt += time_taken
        averages.append(round(total_tt/EXPERIMENTAL_COUNT, 2))
    return averages


def plot_graph(mydig, local, public):
    x = np.arange(len(WEBSITES))  # the label locations
    width = 0.30  # the width of the bars

    fig, ax = plt.subplots()
    rects1 = ax.bar(x - width / 2, mydig, width, label='Custom Dig')
    rects2 = ax.bar(x + width / 2, local, width, label='Local DNS')
    rects3 = ax.bar(x + 1.5 * width, public, width, label='Public DNS(Google)')

    ax.set_ylabel('Average DNS resolution time(in ms)')
    ax.set_xlabel('Website')
    ax.set_title('Performance Test for DNS public, local and custom')
    ax.set_xticks(x, WEBSITES)
    ax.legend(loc='upper right')

    ax.bar_label(rects1, padding=3)
    ax.bar_label(rects2, padding=3)
    ax.bar_label(rects3, padding=3)
    fig.tight_layout()
    plt.grid()
    plt.savefig('./perf_test.png')


if __name__ == '__main__':
    avg_my_dig = performance_test(find_ip, True)
    print(avg_my_dig)
    avg_local_dns = performance_test(resolver_factory(['130.245.255.4']))
    print(avg_local_dns)
    avg_google_dns = performance_test(resolver_factory(['8.8.8.8']))
    print(avg_google_dns)
    plot_graph(avg_my_dig, avg_local_dns, avg_google_dns)
