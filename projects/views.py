from django.db.models import Count
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.views.generic import CreateView, DetailView, ListView

from .forms import TARGET_FORMS
from .models import Project, Target


class ProjectListView(ListView):
    # 대상 수는 저장하지 않고 조회할 때 센다.
    # 집계(GROUP BY)를 쓰면 모델의 기본 정렬이 적용되지 않아서 직접 적는다.
    queryset = Project.objects.annotate(target_count=Count('targets')).order_by('-created_at')


class ProjectCreateView(CreateView):
    model = Project
    # 화면에서 입력받을 칸만 적는다. created_at은 자동으로 채워진다.
    # 기술 스택은 React 등록 화면에서만 입력한다. 이 템플릿 화면은 React로 옮긴 뒤 지운다.
    fields = ['name', 'description']
    success_url = reverse_lazy('home')


class ProjectDetailView(DetailView):
    model = Project


class TargetKindSelectView(DetailView):
    model = Project
    pk_url_kwarg = 'project_pk'
    template_name = 'projects/target_kind_select.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['kinds'] = Target.Kind.choices
        return context


class TargetCreateView(CreateView):
    model = Target

    def dispatch(self, request, *args, **kwargs):
        self.project = get_object_or_404(Project, pk=kwargs['project_pk'])
        self.kind = kwargs['kind']
        if self.kind not in TARGET_FORMS:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_form_class(self):
        return TARGET_FORMS[self.kind]

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        # 프로젝트와 종류는 입력받지 않고 주소에서 정한다.
        kwargs['instance'] = Target(project=self.project, kind=self.kind)
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['project'] = self.project
        context['kind_label'] = Target.Kind(self.kind).label
        return context

    def get_success_url(self):
        return reverse('project_detail', args=[self.project.pk])
